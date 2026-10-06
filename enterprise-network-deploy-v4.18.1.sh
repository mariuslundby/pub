#!/usr/bin/env bash
#
# enterprise-network-deploy.sh — 802.1X / EAP-TLS deployment via NDES-SCEP
#
# v4.0.0  (refaktorert og herdet utgave av v3.5.9)
# Testet mot Fedora 38-44, RHEL/Rocky/Alma 8-10, Debian 12+, Ubuntu 22.04+
#
# ENDRINGER FRA 3.5.9 — se CHANGELOG nederst i fila.
#
# Bruk:
#   sudo ./enterprise-network-deploy.sh [--test] [--verbose] [--no-rollback]
#   sudo ./enterprise-network-deploy.sh --update-pins     # godta ny CA-fingerprint
#   sudo ./enterprise-network-deploy.sh --help
#
# Standardverdiene under er satt opp for Indra Navia og virker uten konfigfil.
# Alt kan overstyres i /etc/enterprise-network-deploy.conf (shell-syntaks)
# eller via miljøvariabler med samme navn.
#
# Innebygde Indra-standarder:
#   VPN_BUNDLE=true            bygger .p12 for FortiClient
#   P12_PASSWORD=Test1234      transportkode for engangsimport
#   P12_TARGET_USER=auto       .p12 på brukerens skrivebord
#   P12_TARGET_SUBDIR          do-not-delete/p12cert
#   EXTRA_TRUST_ANCHORS        RapidSSL TLS RSA CA G1 -> trusted CA, bekreftet
#                              med trust list (trust: anchor)
#   FIX_CHAIN_HOSTS            tom — sett gateway-vert for AIA-reparasjon

if [ -z "${BASH_VERSION:-}" ]; then
    exec /usr/bin/env bash "$0" "$@"
fi

if [ -n "${BASH_VERSINFO:-}" ] && [ "${BASH_VERSINFO[0]}" -lt 4 ]; then
    echo "[ERROR] Krever bash >= 4.0 (fant ${BASH_VERSION})" >&2
    exit 1
fi

# Streng modus. Merk: 'set -e' er bevisst IKKE på — skriptet håndterer feil
# eksplisitt og har mange kommandoer som har lov til å feile. 'set -u' fanger
# skrivefeil i variabelnavn, 'pipefail' fanger feil midt i pipelines.
set -uo pipefail
shopt -s nullglob

umask 077
export LC_ALL=C
export PATH="/usr/sbin:/usr/bin:/sbin:/bin"
IFS=$' \t\n'

readonly SCRIPT_VERSION="4.18.1"
readonly SCRIPT_NAME="${0##*/}"

# ═════════════════════════════════════════════════════════════════════════════
# KONFIGURASJON  (kan overstyres i /etc/enterprise-network-deploy.conf)
# ═════════════════════════════════════════════════════════════════════════════

CONFIG_FILE="${CONFIG_FILE:-/etc/enterprise-network-deploy.conf}"
CONFIG_LOADED=false

# --- SCEP / PKI --------------------------------------------------------------
SCEP_URL="${SCEP_URL:-https://ndesscep-indranavia.msappproxy.net/certsrv/mscep/mscep.dll}"
CA_NAME="${CA_NAME:-NDES}"
DOMAIN_SUFFIX="${DOMAIN_SUFFIX:-ad.indra.no}"

# Server-identitetskontroll for 802.1X (herding — se SIKKERHET i CHANGELOG).
# Tvinger klienten til å kreve at RADIUS-serverens sertifikat har et navn som
# slutter på dette suffikset. Uten dette kan ETHVERT sertifikat utstedt av
# CA-en brukes til å utgi seg for RADIUS-serveren.
# Sett til "" for å slå av (ikke anbefalt).
RADIUS_DOMAIN_SUFFIX="${RADIUS_DOMAIN_SUFFIX:-${DOMAIN_SUFFIX}}"

# Krev at CA-kjeden matcher tidligere sett fingerprint (TOFU-pinning).
CA_PINNING="${CA_PINNING:-true}"

# Legg Enterprise/Root CA inn i systemets trust store. RA-sertifikatet legges
# ALDRI inn (det er et endepunkt-sertifikat, ikke et anker).
INSTALL_CA_IN_TRUST_STORE="${INSTALL_CA_IN_TRUST_STORE:-true}"

# Tillat usikret TLS mot SCEP-endepunktet (curl -k). Kun for interne
# endepunkt med selvsignert TLS-sert. Standard: AV.
ALLOW_INSECURE_TLS="${ALLOW_INSECURE_TLS:-false}"

# SHA-1-håndtering: auto | scoped | global | off
#   scoped = kun certmonger får SHA-1 (systemd drop-in)   <- tryggest
#   global = update-crypto-policies ...:SHA1              <- svekker HELE systemet
#   auto   = prøv scoped, eskaler til global kun ved behov
SHA1_MODE="${SHA1_MODE:-auto}"

# Be om eksplisitt Key Usage / EKU i CSR. Standard AV — NDES-malen styrer
# normalt dette, og feil verdier her gir CA_REJECTED.
REQUEST_EKU="${REQUEST_EKU:-false}"
KEY_SIZE="${KEY_SIZE:-}"          # tom = certmonger-standard (2048)

# --- Sti-oppsett -------------------------------------------------------------
CERT_BASE_PATH="${CERT_BASE_PATH:-/etc/pki/802.1x}"
MACHINE_CERT="${CERT_BASE_PATH}/machine.crt"
MACHINE_KEY="${CERT_BASE_PATH}/machine.key"
CA_CERT="${CERT_BASE_PATH}/ca-chain.pem"
PIN_FILE="${CERT_BASE_PATH}/ca-pins.sha256"

CERTMONGER_CERT_DIR="/var/lib/certmonger"
PERM_RA_ENC="${CERTMONGER_CERT_DIR}/scep-ra-enc.crt"
PERM_RA_SIGN="${CERTMONGER_CERT_DIR}/scep-ra-sign.crt"
PERM_CA_CHAIN="${CERTMONGER_CERT_DIR}/scep-ca-chain.crt"
PERM_ENTERPRISE_CA="${CERTMONGER_CERT_DIR}/scep-enterprise-ca.crt"
PERM_ALL_CERTS="${CERTMONGER_CERT_DIR}/scep-all-certs.crt"

# --- NetworkManager ----------------------------------------------------------
WIRED_CONNECTION_NAME="${WIRED_CONNECTION_NAME:-Wired-802.1x}"
WIRED_PRIORITY="${WIRED_PRIORITY:-100}"
WIFI_CONNECTION_NAME="${WIFI_CONNECTION_NAME:-IndraNavia}"
WIFI_SSID="${WIFI_SSID:-IndraNavia}"
WIFI_PRIORITY="${WIFI_PRIORITY:-50}"
EAP_METHOD="${EAP_METHOD:-tls}"
EXISTING_FALLBACK_PRIORITY="${EXISTING_FALLBACK_PRIORITY:-5}"
OLD_INDRA_PRIORITY="${OLD_INDRA_PRIORITY:-1}"
OLD_PROFILE_MATCH="${OLD_PROFILE_MATCH:-indra}"

# --- VPN-klientpakke (FortiClient m.fl.) -------------------------------------
# Bygger PKCS#12 av maskin-sertifikatet og installerer ekstra trust anchors.
# Kjører uavhengig av om VPN-klienten faktisk er installert.
VPN_BUNDLE="${VPN_BUNDLE:-true}"           # true | false
# "" = systemsti (${CERT_BASE_PATH}) — tryggeste standard.
# "auto" = brukeren som kjørte sudo. Eller et konkret brukernavn.
# "auto"  = hjemmekatalogen til brukeren som kjørte sudo  (standard)
# ""      = systemvidt i ${CERT_BASE_PATH}
# "navn"  = en bestemt bruker
# .p12 er ren transport: FortiClient tar sin egen kopi ved import, og fila
# ryddes bort etter P12_RETENTION_DAYS. Derfor skal den ligge et sted
# brukeren faktisk finner den.
P12_TARGET_USER="${P12_TARGET_USER:-auto}"
# Hvem .p12 ble lagt hos sist. Brukes før all gjetting, slik at fornyelses-
# hooken (som kjører uten terminal) og senere kjøringer treffer samme bruker.
P12_TARGET_USER_FILE="${P12_TARGET_USER_FILE:-${CERT_BASE_PATH}/p12-target-user}"
# Kontoer som ALDRI er sluttbruker — den lokale adminkontoen fra imaget.
# Standard: "user". Mellomromsseparert. Tom verdi (P12_EXCLUDE_USERS="") slår
# det av. Gjør utrulling via ManageEngine o.l.
# entydig: agenten kjører uten terminal og kan ikke spørre, og med
# adminkontoen utelatt blir sluttbrukeren eneste kandidat.
# --user <navn> vinner over denne lista.
P12_EXCLUDE_USERS="${P12_EXCLUDE_USERS-user}"
# Lokal passwd-fil. Brukere som IKKE står her er domenebrukere (AD/SSSD).
LOCAL_PASSWD_FILE="${LOCAL_PASSWD_FILE:-/etc/passwd}"
# Undermappe i hjemmekatalogen. Enten et nøkkelord som slås opp med
# xdg-user-dir (DESKTOP, DOWNLOAD — treffer lokaliserte navn som Skrivebord),
# eller en vanlig relativ sti som opprettes hvis den mangler.
#
# Standard er en egen mappe med et navn som sier fra: FortiClient lagrer
# STIEN til .p12 sammen med passordet og leser fila ved hver tilkobling.
# Flyttes eller slettes den, slutter VPN-en å virke. På skrivebordet er den
# for lett å rydde bort ved et uhell.
P12_TARGET_SUBDIR="${P12_TARGET_SUBDIR:-do-not-delete/p12cert}"

# Importer .p12 i brukerens NSS-database (~/.pki/nssdb) i tillegg til å legge
# fila på skrivebordet. Det er brukersertifikatlageret Chromium, Evolution m.fl.
# leser fra på Linux. Leser FortiClient sertifikatlista derfra, slipper
# brukeren å importere manuelt. Skader ikke om den ikke gjør det.
# Fortinet dokumenterer INGEN CLI-import for Linux, så dette er uverifisert
# for FortiClient spesifikt — derfor av som standard.
P12_IMPORT_NSS="${P12_IMPORT_NSS:-false}"
P12_FILENAME="${P12_FILENAME:-indra-machine.p12}"
P12_FRIENDLY_NAME="${P12_FRIENDLY_NAME:-Indra Machine}"
# fixed  = P12_PASSWORD under, likt på alle maskiner (enkel helpdesk-flyt)
# random = 128 bit per maskin, lagres i P12_PASSWORD_FILE
# file   = les fra P12_PASSWORD_FILE
# env    = les fra miljøvariabelen P12_PASS (synlig i /proc — frarådes)
P12_PASSWORD_MODE="${P12_PASSWORD_MODE:-fixed}"
P12_PASSWORD="${P12_PASSWORD:-Test1234}"

# Antall dager før den utleverte .p12-fila ryddes bort. 0 = behold for alltid.
#
# STANDARD ER 0, og det er et bevisst valg: FortiClient på Linux ser ut til å
# lagre STIEN til .p12-fila sammen med passordet, ikke bare innholdet. Sletter
# man fila, kan VPN-en slutte å virke — og da skjer det to uker etter
# utrulling, på alle maskiner samtidig, uten åpenbar årsak.
#
# Verifiser på én maskin før du slår på opprydding:
#     mv ~/Desktop/indra-machine.p12 /tmp/
#     <koble til VPN på nytt>
# Virker VPN fortsatt, har FortiClient tatt sin egen kopi. Sett da f.eks. 14.
#
# Fram til det: fila blir liggende. Den inneholder maskinens privatnøkkel bak
# et passord som er likt på hele flåten, så rettighetene (0600) og at
# katalogen ikke synkroniseres eller backes opp er det som beskytter den.
P12_RETENTION_DAYS="${P12_RETENTION_DAYS:-0}"
P12_DELIVERED_MARKER="${CERT_BASE_PATH}/.p12-delivered"
P12_PASSWORD_FILE="${P12_PASSWORD_FILE:-${CERT_BASE_PATH}/p12-password}"
P12_COMPAT="${P12_COMPAT:-auto}"           # auto | true | false (3DES/SHA1 for eldre klienter)

EXTRA_TRUST_ANCHORS=( ${EXTRA_TRUST_ANCHORS[@]+"${EXTRA_TRUST_ANCHORS[@]}"} )
# Ekstra trust anchors: "https://url/cert.crt" eller "https://url/cert.crt|<sha256>"
# Må kjede til noe systemet allerede stoler på (se EXTRA_ANCHOR_REQUIRE_CHAIN).
#
# STANDARD: RapidSSL TLS RSA CA G1 — mellom-CA-et FortiGaten ikke sender i
# IKEv2-handshaken. Uten det feiler FortiClient med
#   ca_validate_cert: /CN=*.indra.no unable to get local issuer certificate
#
# Framgangsmåten er den samme som manuelt:
#   1. hent fra DigiCerts offisielle AIA-adresse
#   2. konverter DER -> PEM
#   3. kontroller at det kjeder til en rot systemet ALLEREDE stoler på
#      (et innsatt/falskt sertifikat avvises her, uansett transport)
#   4. legg i /etc/pki/ca-trust/source/anchors/ og kjør update-ca-trust extract
#   5. bekreft med p11-kit (trust list) at det står som "trust: anchor"
#
# Forvaltes mellom-CA-et manuelt i stedet, sett i konfigfila:
#   EXTRA_TRUST_ANCHORS=()
# Da kontrollerer skriptet bare at kjeden virker (VPN_CHAIN_CHECK).
# (Konfigfila lastes etter dette, så EXTRA_TRUST_ANCHORS=() der overstyrer.)
if [ "${#EXTRA_TRUST_ANCHORS[@]}" -eq 0 ]; then
    EXTRA_TRUST_ANCHORS=( "http://cacerts.rapidssl.com/RapidSSLTLSRSACAG1.crt" )
fi
EXTRA_ANCHOR_REQUIRE_CHAIN="${EXTRA_ANCHOR_REQUIRE_CHAIN:-true}"

# --- Kontroll av VPN-kjeden (kun lesing, installerer ingenting) --------------
# Sjekker at systemets trust store kan validere VPN-gatewayens sertifikat.
# Med GATEWAY_CERT / GATEWAY_CERT_STORE valideres selve gateway-sertifikatet
# (sterkest). Uten det sjekkes det at forventet utsteder finnes i trust store.
VPN_CHAIN_CHECK="${VPN_CHAIN_CHECK:-true}"
VPN_CHAIN_EXPECT_ISSUER="${VPN_CHAIN_EXPECT_ISSUER:-RapidSSL TLS RSA CA G1}"
# Filnavn tidligere skriptversjoner (4.9-4.13) brukte. Rapporteres som
# rester hvis de finnes, slik at det er tydelig hva som kom fra skriptet.
SCRIPT_ANCHOR_LEFTOVERS=(RapidSSLTLSRSACAG1 RapidSSL_TLS_RSA_CA_G1)

# Hvordan et mellom-CA legges inn:
#   chain-only = /etc/pki/ca-trust/source/         (nøytral tillit)
#                Sertifikatet blir KJENT for systemet så kjeder kan bygges,
#                men er ikke selv et tillitsanker. Tilliten kommer fortsatt
#                fra rot-CA-en. Dette er den snevreste varianten.
#   anchor     = /etc/pki/ca-trust/source/anchors/ (tillitsanker) — STANDARD
#                Dette er "trusted certificate authorities" på Linux, og den
#                forutsigbare varianten: sertifikatet havner alltid i bundlen
#                klientene leser.
#   auto       = prøv chain-only, MÅL om det faktisk når fram til bundlen
#                OpenSSL-klienter leser, og eskaler til anchor hvis ikke.
#
# Hvorfor auto og ikke chain-only: p11-kit legger nøytrale sertifikater inn
# med tomme trust-flagg, og de havner ikke i den ekstraherte
# tls-ca-bundle.pem som OpenSSL-baserte klienter (som FortiClient) leser.
# Om det virker avhenger av p11-kit-versjonen, så skriptet måler i stedet
# for å anta.
EXTRA_ANCHOR_MODE="${EXTRA_ANCHOR_MODE:-anchor}"

# Gatewayer som ikke sender hele kjeden i handshaken. Skriptet henter de
# manglende mellom-CA-ene via AIA (slik Windows gjør) og legger dem lokalt.
# Format: "vert" eller "vert:port". Eks: ("vpn.indra.no:443")
FIX_CHAIN_HOSTS=( ${FIX_CHAIN_HOSTS[@]+"${FIX_CHAIN_HOSTS[@]}"} )

# Gatewayens eget sertifikat (leaf), som PEM- eller DER-fil. Brukes til å
# finne mellom-CA-et via AIA UTEN å måtte nå gatewayen over nettet — og,
# viktigere, som verifikasjonsmål etterpå: validerer DETTE sertifikatet mot
# trust store, er kjeden beviselig komplett.
# Kopieres til GATEWAY_CERT_STORE ved første kjøring, så senere kjøringer og
# --status kan bruke det.
GATEWAY_CERT="${GATEWAY_CERT:-}"
GATEWAY_CERT_STORE="${GATEWAY_CERT_STORE:-${CERT_BASE_PATH}/gateway-cert.pem}"
# Varsle når gateway-sertifikatet nærmer seg utløp (dager).
GATEWAY_CERT_WARN_DAYS="${GATEWAY_CERT_WARN_DAYS:-45}"

# Certmonger kaller denne etter hver fornyelse, slik at .p12 ikke blir
# stående med en utdatert nøkkel. Krever at skriptet installeres på fast sti.
# --- FortiClient --------------------------------------------------------------
# Lokal sti eller https://-URL til RPM-en. Tom = hopp over hele stadiet.
FORTICLIENT_RPM="${FORTICLIENT_RPM:-}"
FORTICLIENT_RPM_SHA256="${FORTICLIENT_RPM_SHA256:-}"
FORTICLIENT_EXPECTED_VERSION="${FORTICLIENT_EXPECTED_VERSION:-}"
# EMS-genererte pakker er ompakket og mangler ofte Fortinets signatur.
FORTICLIENT_REQUIRE_SIGNATURE="${FORTICLIENT_REQUIRE_SIGNATURE:-false}"
# Nedgradering (f.eks. 7.4.8 -> 7.4.7) må være et bevisst valg.
FORTICLIENT_ALLOW_DOWNGRADE="${FORTICLIENT_ALLOW_DOWNGRADE:-true}"
FORTICLIENT_VERSIONLOCK="${FORTICLIENT_VERSIONLOCK:-true}"

# EMS-registrering — dette er koden brukeren ellers må taste inn manuelt.
EMS_INVITATION_CODE="${EMS_INVITATION_CODE:-}"
EMS_SERVER="${EMS_SERVER:-}"
EMS_SITE="${EMS_SITE:-}"

RENEW_HOOK="${RENEW_HOOK:-true}"
INSTALL_PATH="${INSTALL_PATH:-/usr/local/sbin/enterprise-network-deploy.sh}"
RENEW_HOOK_PATH="${RENEW_HOOK_PATH:-/usr/local/sbin/enterprise-network-8021x-renew-hook}"
P12_FP_MARKER="${CERT_BASE_PATH}/.p12-cert-fingerprint"

# --- Logging / tilstand ------------------------------------------------------
LOG_FILE="${LOG_FILE:-/var/log/enterprise-network-deployment.log}"
ROLLBACK_LOG="${ROLLBACK_LOG:-/var/log/enterprise-network-rollback.log}"
RUNTIME_DIR="/run/enterprise-network-deploy"
STATE_FILE="${RUNTIME_DIR}/state"
LOCK_FILE="${RUNTIME_DIR}/lock"

ENROLL_TIMEOUT="${ENROLL_TIMEOUT:-180}"

# --- Kjøretidsflagg ----------------------------------------------------------
TEST_MODE=false
VERBOSE=false
DO_ROLLBACK=true
UPDATE_PINS=false
CONFIG_LOADED=false
CLI_P12_USER=""
CLI_P12_EXCLUDE=""
FORCE_P12=false
RUN_MODE="deploy"          # deploy | status | vpn-only

# Interne (ikke konfigurerbare)
WORKDIR=""
SYSTEM_CA_BUNDLE=""
WIRED_INTERFACES=""
ACTIVE_WIRED_CONNECTION=""
ACTIVE_WIFI_CONNECTION=""
OS=""
OS_VERSION=""
HOSTNAME_SHORT=""
FQDN=""
LOCK_FD=""
SHA1_GLOBAL_APPLIED=false
LAST_P12_PATH=""

# ═════════════════════════════════════════════════════════════════════════════
# ARGUMENTPARSING
# ═════════════════════════════════════════════════════════════════════════════

usage() {
    cat <<USAGE
${SCRIPT_NAME} v${SCRIPT_VERSION} — 802.1X/EAP-TLS deployment via NDES-SCEP

  --test          Tørrkjøring. Ingen endringer på systemet.
  --verbose       Skriv debug-linjer også til konsoll.
  --no-rollback   Ikke rull tilbake automatisk ved feil (for feilsøking).
  --update-pins   Godta og lagre ny CA-fingerprint (ved planlagt CA-bytte).
  --vpn-bundle    Bygg PKCS#12 + installer ekstra trust anchors (VPN-klient).
  --no-vpn-bundle Hopp over VPN-klientpakka selv om den er slått på i konfig.
  --vpn-bundle-only  Kjør KUN VPN-klientpakka (trust anchors + .p12).
                     Brukes av certmonger sin fornyelseshook.
  --force-p12     Bygg .p12 på nytt selv om sertifikatet er uendret.
  --user <navn>   Sluttbrukeren som skal ha .p12 (den som bruker FortiClient).
                  Bruk når en tekniker kjører skriptet. Valget huskes, så
                  fornyelseshooken og senere kjøringer treffer samme bruker.
  --exclude-user <navn>
                  Konto som aldri er sluttbruker, f.eks. lokal admin fra
                  imaget. Kan gjentas. For utrulling uten terminal (ME):
                  da blir sluttbrukeren eneste kandidat.
  --status        Vis gjeldende tilstand. Endrer ingenting.
  --forticlient-only  Kjør KUN FortiClient-installasjon + EMS-registrering.
  --cleanup-p12   Rydd bort utleverte .p12-filer eldre enn P12_RETENTION_DAYS.
  --fix-chain <vert[:port]>
                  Hent manglende mellom-CA via AIA og installer dem lokalt.
                  Fikser "unable to get local issuer certificate" uten å
                  røre gatewayen.
  --gateway-cert <fil>
                  Samme, men med utgangspunkt i gatewayens sertifikatfil
                  (PEM/DER/PKCS#7) i stedet for en nettverksforbindelse.
                  Sertifikatet brukes også som verifikasjonsmål: validerer
                  det etterpå, er kjeden beviselig komplett.
  --version       Skriv versjon og avslutt.
  -h, --help      Denne teksten.

Konfigurasjon leses fra ${CONFIG_FILE} hvis den finnes.
USAGE
}

while [ $# -gt 0 ]; do
    case "$1" in
        --test)         TEST_MODE=true ;;
        --verbose|-v)   VERBOSE=true ;;
        --no-rollback)  DO_ROLLBACK=false ;;
        --update-pins)  UPDATE_PINS=true ;;
        --vpn-bundle)   VPN_BUNDLE=true ;;
        --no-vpn-bundle) VPN_BUNDLE=false ;;
        --vpn-bundle-only) RUN_MODE="vpn-only"; VPN_BUNDLE=true ;;
        --force-p12)    FORCE_P12=true ;;
        --user)
            shift
            [ $# -gt 0 ] && [ -n "$1" ] || { echo "[ERROR] --user krever et brukernavn" >&2; exit 2; }
            CLI_P12_USER="$1"
            ;;
        --exclude-user)
            shift
            [ $# -gt 0 ] && [ -n "$1" ] || { echo "[ERROR] --exclude-user krever et brukernavn" >&2; exit 2; }
            CLI_P12_EXCLUDE="${CLI_P12_EXCLUDE:+$CLI_P12_EXCLUDE }$1"
            ;;
        --status)       RUN_MODE="status" ;;
        --forticlient-only) RUN_MODE="forticlient-only" ;;
        --cleanup-p12)  RUN_MODE="cleanup-p12" ;;
        --fix-chain)
            shift
            [ $# -gt 0 ] || { echo "[ERROR] --fix-chain krever vert[:port]" >&2; exit 2; }
            FIX_CHAIN_HOSTS+=("$1")
            RUN_MODE="fix-chain"
            ;;
        --gateway-cert)
            shift
            [ $# -gt 0 ] || { echo "[ERROR] --gateway-cert krever en filsti" >&2; exit 2; }
            GATEWAY_CERT="$1"
            RUN_MODE="fix-chain"
            ;;
        --version)      echo "${SCRIPT_NAME} ${SCRIPT_VERSION}"; exit 0 ;;
        -h|--help)      usage; exit 0 ;;
        *)
            echo "[ERROR] Ukjent argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
    shift
done

# Konfigfil lastes ETTER argumenter, men verdiene over er allerede satt med
# ${VAR:-default}, så konfigfila vinner over defaults og miljø vinner over alt
# hvis den bruker samme mønster. Vi laster derfor i subshell-sjekk først.
if [ -f "$CONFIG_FILE" ]; then
    if [ "$(stat -c '%U' "$CONFIG_FILE" 2>/dev/null)" != "root" ]; then
        echo "[ERROR] $CONFIG_FILE eies ikke av root — nekter å laste" >&2
        exit 1
    fi
    CONFIG_PERM=$(stat -c '%a' "$CONFIG_FILE" 2>/dev/null || echo 777)
    if [ $(( 8#$CONFIG_PERM & 8#022 )) -ne 0 ]; then
        echo "[ERROR] $CONFIG_FILE er skrivbar for andre enn root (${CONFIG_PERM})" >&2
        exit 1
    fi
    # shellcheck disable=SC1090
    . "$CONFIG_FILE"
    CONFIG_LOADED=true
fi
# Kommandolinjen vinner over konfigfila.
[ -n "${CLI_P12_USER:-}" ] && P12_TARGET_USER="$CLI_P12_USER"
[ -n "${CLI_P12_EXCLUDE:-}" ] && P12_EXCLUDE_USERS="${P12_EXCLUDE_USERS:+$P12_EXCLUDE_USERS }$CLI_P12_EXCLUDE"

if [ "$TEST_MODE" = true ]; then
    echo "=== TEST MODE ==="
    echo "Ingen endringer gjøres på systemet."
    echo ""
fi

# ═════════════════════════════════════════════════════════════════════════════
# LOGGING
# ═════════════════════════════════════════════════════════════════════════════

_ts() { date '+%Y-%m-%d %H:%M:%S'; }

_logfile_write() {
    [ -n "${LOG_FILE:-}" ] || return 0
    printf '[%s] %s\n' "$(_ts)" "$1" >> "$LOG_FILE" 2>/dev/null || true
}

log()         { _logfile_write "$1";           printf '[LOG] %s\n' "$1"; }
log_warn()    { _logfile_write "WARN: $1";     printf '[WARN] %s\n' "$1"; }
log_success() { _logfile_write "OK: $1";       printf '[OK] %s\n' "$1"; }
log_error()   { _logfile_write "ERROR: $1";    printf '[ERROR] %s\n' "$1" >&2; }
log_debug()   {
    _logfile_write "DEBUG: $1"
    [ "$VERBOSE" = true ] && printf '[DEBUG] %s\n' "$1"
    return 0
}

log_section() {
    {
        echo ""
        echo "=========================================="
        printf '[%s] %s\n' "$(_ts)" "$1"
        echo "=========================================="
    } >> "$LOG_FILE" 2>/dev/null || true
    printf '\n=== %s ===\n' "$1"
}

# Logg kommandoutdata uten å vise det på konsoll (med mindre --verbose).
log_output() {
    if [ "$VERBOSE" = true ]; then
        tee -a "$LOG_FILE"
    else
        cat >> "$LOG_FILE" 2>/dev/null || cat > /dev/null
    fi
}

init_logging() {
    if [ "$TEST_MODE" = true ]; then
        # Tørrkjøring skal ikke røre /var/log og skal kunne kjøres uten root.
        LOG_FILE="$(mktemp -t enterprise-deploy-test.XXXXXX)"
        chmod 600 "$LOG_FILE"
        return 0
    fi
    # install -m sikrer at fila aldri finnes med for åpne rettigheter,
    # heller ikke i et vindu mellom touch og chmod (som i v3.5.9).
    local f
    for f in "$LOG_FILE" "$ROLLBACK_LOG"; do
        if [ ! -e "$f" ]; then
            install -m 0600 -o root -g root /dev/null "$f" 2>/dev/null || {
                echo "[ERROR] Kan ikke opprette loggfil: $f" >&2
                exit 1
            }
        else
            # Nekt å skrive til en symlink (root-symlink-angrep).
            if [ -L "$f" ]; then
                echo "[ERROR] Loggfil er en symlink — avbryter: $f" >&2
                exit 1
            fi
            chmod 0600 "$f" 2>/dev/null || true
        fi
    done
}

# ═════════════════════════════════════════════════════════════════════════════
# LÅS, TEMP-KATALOG, TILSTAND
# ═════════════════════════════════════════════════════════════════════════════

acquire_lock() {
    [ "$TEST_MODE" = true ] && return 0
    install -d -m 0700 "$RUNTIME_DIR" || {
        log_error "Kan ikke opprette $RUNTIME_DIR"
        exit 1
    }
    exec {LOCK_FD}>"$LOCK_FILE" || {
        log_error "Kan ikke åpne låsefil"
        exit 1
    }
    if ! flock -n "$LOCK_FD"; then
        log_error "En annen instans av $SCRIPT_NAME kjører allerede. Avbryter."
        exit 1
    fi
    log_debug "Lås tatt: $LOCK_FILE"
}

init_workdir() {
    # v3.5.9 brukte faste /tmp-stier. Som root er det sårbart for
    # symlink-/forutsigbarhetsangrep fra lokale brukere. Egen 0700-katalog.
    WORKDIR="$(mktemp -d -p "${TMPDIR:-/tmp}" enterprise-deploy.XXXXXXXX)" || {
        echo "[ERROR] mktemp feilet" >&2
        exit 1
    }
    chmod 0700 "$WORKDIR"
    log_debug "Arbeidskatalog: $WORKDIR"

    TMP_BUNDLE="$WORKDIR/ndes-ca-bundle.crt"
    TMP_RA="$WORKDIR/ndes-ra-sign.crt"
    TMP_CA_CHAIN="$WORKDIR/ndes-ca-chain.crt"
    TMP_RA_ENC="$WORKDIR/ndes-ra-enc.crt"
    TMP_RA_COMBINED="$WORKDIR/ndes-ra-combined.crt"
    TMP_SPLIT_DIR="$WORKDIR/split"
    mkdir -p "$TMP_SPLIT_DIR"
}

record_state() {
    [ "$TEST_MODE" = true ] && return 0
    install -d -m 0700 "$RUNTIME_DIR" 2>/dev/null || true
    printf '%s\n' "$1" >> "$STATE_FILE"
    chmod 0600 "$STATE_FILE" 2>/dev/null || true
    log_debug "Rollback-punkt: $1"
}

# Sikkerhetskopi som rollback kan bruke. Lagres i root-only runtime-katalog,
# ikke ved siden av originalen (der en angriper kunne plassert egen fil).
backup_for_rollback() {
    local src="$1"
    [ -f "$src" ] || return 0
    local id backup
    id="$(printf '%s' "$src" | tr '/' '_')"
    backup="${RUNTIME_DIR}/backup${id}"
    install -d -m 0700 "$RUNTIME_DIR"
    cp -a "$src" "$backup" || return 1
    record_state "FILE_MODIFIED:${src}"
    log_debug "Backup: $src -> $backup"
}

# ═════════════════════════════════════════════════════════════════════════════
# ROLLBACK
# ═════════════════════════════════════════════════════════════════════════════

rollback() {
    [ -f "$STATE_FILE" ] || return 0
    [ "$DO_ROLLBACK" = false ] && {
        log_warn "--no-rollback aktiv — hopper over tilbakerulling. Tilstand: $STATE_FILE"
        return 0
    }

    log_error "Deployment feilet — ruller tilbake..."
    printf '[%s] === ROLLBACK STARTED ===\n' "$(_ts)" >> "$ROLLBACK_LOG"

    local rollback_ok=true action

    # Rull tilbake i omvendt rekkefølge (LIFO) — v3.5.9 gjorde FIFO, som kan
    # gjenopprette i feil rekkefølge når flere endringer henger sammen.
    while IFS= read -r action; do
        [ -z "$action" ] && continue
        printf '[%s] Behandler: %s\n' "$(_ts)" "$action" >> "$ROLLBACK_LOG"

        case "$action" in
            CERT_REQUESTED:*)
                local req_id="${action#CERT_REQUESTED:}"
                log "Ruller tilbake sertifikatforespørsel: $req_id"
                if getcert stop-tracking -i "$req_id" >/dev/null 2>&1; then
                    echo "  OK  stoppet sporing: $req_id" >> "$ROLLBACK_LOG"
                else
                    echo "  FEIL stoppe sporing: $req_id" >> "$ROLLBACK_LOG"
                    rollback_ok=false
                fi
                ;;
            CONNECTION_CREATED:*)
                local conn="${action#CONNECTION_CREATED:}"
                log "Ruller tilbake NM-profil: $conn"
                if nmcli connection delete "$conn" >/dev/null 2>&1; then
                    echo "  OK  slettet profil: $conn" >> "$ROLLBACK_LOG"
                else
                    echo "  FEIL slette profil: $conn" >> "$ROLLBACK_LOG"
                    rollback_ok=false
                fi
                ;;
            FILE_MODIFIED:*)
                local path="${action#FILE_MODIFIED:}"
                local id backup
                id="$(printf '%s' "$path" | tr '/' '_')"
                backup="${RUNTIME_DIR}/backup${id}"
                if [ -f "$backup" ]; then
                    log "Gjenoppretter fil: $path"
                    if cp -a "$backup" "$path"; then
                        echo "  OK  gjenopprettet: $path" >> "$ROLLBACK_LOG"
                    else
                        echo "  FEIL gjenopprette: $path" >> "$ROLLBACK_LOG"
                        rollback_ok=false
                    fi
                fi
                ;;
            FILE_CREATED:*)
                local path="${action#FILE_CREATED:}"
                log "Fjerner opprettet fil: $path"
                rm -f "$path" && echo "  OK  fjernet: $path" >> "$ROLLBACK_LOG"
                ;;
            CA_ADDED:*)
                local ca="${action#CA_ADDED:}"
                log "Ruller tilbake CA: $ca"
                if getcert remove-ca -c "$ca" >/dev/null 2>&1; then
                    echo "  OK  fjernet CA: $ca" >> "$ROLLBACK_LOG"
                else
                    echo "  FEIL fjerne CA: $ca" >> "$ROLLBACK_LOG"
                    rollback_ok=false
                fi
                ;;
            CRYPTO_POLICY_CHANGED:*)
                # v3.5.9 registrerte dette, men hadde INGEN handler — den globale
                # krypto-svekkelsen ble aldri rullet tilbake.
                local prev="${action#CRYPTO_POLICY_CHANGED:}"
                log "Gjenoppretter crypto policy: $prev"
                if update-crypto-policies --set "$prev" >/dev/null 2>&1; then
                    echo "  OK  crypto policy tilbake til: $prev" >> "$ROLLBACK_LOG"
                else
                    echo "  FEIL crypto policy: $prev" >> "$ROLLBACK_LOG"
                    rollback_ok=false
                fi
                ;;
            SERVICE_STATE:*)
                local svc="${action#SERVICE_STATE:}"
                log "Gjenoppretter tjeneste: $svc"
                systemctl restart "$svc" >/dev/null 2>&1 || true
                ;;
        esac
    done < <(tac "$STATE_FILE" 2>/dev/null || cat "$STATE_FILE")

    rm -f "$STATE_FILE"

    if [ "$rollback_ok" = true ]; then
        printf '[%s] === ROLLBACK COMPLETED ===\n' "$(_ts)" >> "$ROLLBACK_LOG"
        log_error "Tilbakerulling ferdig. Logger: $LOG_FILE og $ROLLBACK_LOG"
    else
        printf '[%s] === ROLLBACK COMPLETED WITH ERRORS ===\n' "$(_ts)" >> "$ROLLBACK_LOG"
        log_error "Tilbakerulling med feil — manuell opprydding kan kreves: $ROLLBACK_LOG"
    fi
}

cleanup_on_exit() {
    local exit_code=$?
    trap - EXIT INT TERM

    if [ -n "$WORKDIR" ] && [ -d "$WORKDIR" ]; then
        # Kjeden inneholder ingen hemmeligheter, men privatnøkkelmateriale kan
        # havne her ved fremtidige endringer — slett grundig.
        find "$WORKDIR" -type f -exec shred -u {} + 2>/dev/null || true
        rm -rf "$WORKDIR"
    fi

    if [ "$exit_code" -ne 0 ] && [ "$TEST_MODE" = false ]; then
        log_error "Skriptet avsluttet med kode: $exit_code"
        rollback
        echo "FEILET: Deployment feilet på $(hostname). Logg: $LOG_FILE" >&2
    else
        rm -f "$STATE_FILE" 2>/dev/null || true
        if [ "$TEST_MODE" = true ]; then
            echo ""
            echo "=== TEST MODE FERDIG — ingen endringer gjort ==="
            echo "Testlogg: $LOG_FILE"
        fi
    fi
    exit "$exit_code"
}

on_signal() {
    log_error "Avbrutt av signal — rydder opp"
    exit 130
}

trap cleanup_on_exit EXIT
trap on_signal INT TERM

# ═════════════════════════════════════════════════════════════════════════════
# KOMMANDOKJØRING
# ═════════════════════════════════════════════════════════════════════════════

# v3.5.9 brukte eval "$command" — strengbasert kjøring med
# injeksjonsflate. Her kjøres kommandoen som argumentarray.
run() {
    local desc="$1"; shift
    log_debug "Kjører: $desc :: $*"

    if [ "$TEST_MODE" = true ]; then
        log "[TEST] Ville kjørt: $desc"
        return 0
    fi

    if "$@" >> "$LOG_FILE" 2>&1; then
        log_success "$desc"
        return 0
    fi
    local rc=$?
    log_error "$desc feilet (exit $rc)"
    return "$rc"
}

run_optional() {
    local desc="$1"; shift
    if ! run "$desc" "$@"; then
        log_warn "Ikke-kritisk feil — fortsetter: $desc"
    fi
    return 0
}

require_cmd() {
    local c
    for c in "$@"; do
        command -v "$c" >/dev/null 2>&1 || {
            log_error "Mangler påkrevd kommando: $c"
            return 1
        }
    done
    return 0
}

# ═════════════════════════════════════════════════════════════════════════════
# HTTPS-HENTING  (erstatter curl -k)
# ═════════════════════════════════════════════════════════════════════════════

http_get() {
    local url="$1" outfile="$2"
    local -a args=(
        --silent --show-error --fail --location
        --proto '=https' --proto-redir '=https'
        --tlsv1.2
        --connect-timeout 10 --max-time 60
        --retry 2 --retry-delay 3
        --output "$outfile"
    )

    if [ "$ALLOW_INSECURE_TLS" = true ]; then
        args+=(--insecure)
    elif [ -n "$SYSTEM_CA_BUNDLE" ]; then
        args+=(--cacert "$SYSTEM_CA_BUNDLE")
    fi

    curl "${args[@]}" "$url" 2>> "$LOG_FILE"
}

http_head() {
    local url="$1"
    local -a args=(
        --silent --show-error --fail --head --location
        --proto '=https' --tlsv1.2
        --connect-timeout 10 --max-time 20
        --output /dev/null
    )
    if [ "$ALLOW_INSECURE_TLS" = true ]; then
        args+=(--insecure)
    elif [ -n "$SYSTEM_CA_BUNDLE" ]; then
        args+=(--cacert "$SYSTEM_CA_BUNDLE")
    fi
    curl "${args[@]}" "$url" 2>> "$LOG_FILE"
}

# ═════════════════════════════════════════════════════════════════════════════
# SYSTEM CA BUNDLE
# ═════════════════════════════════════════════════════════════════════════════

detect_system_ca_bundle() {
    local p
    for p in \
        /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem \
        /etc/pki/tls/certs/ca-bundle.crt \
        /etc/ssl/certs/ca-certificates.crt \
        /etc/ssl/cert.pem
    do
        if [ -f "$p" ] && [ -s "$p" ]; then
            SYSTEM_CA_BUNDLE="$p"
            log_debug "System CA bundle: $p"
            return 0
        fi
    done
    log_error "Fant ingen system-CA-bundle. Installer ca-certificates og kjør update-ca-trust extract."
    return 1
}

# ═════════════════════════════════════════════════════════════════════════════
# SELINUX
# ═════════════════════════════════════════════════════════════════════════════

# chcon alene overlever ikke en full relabel. semanage + restorecon er varig.
set_selinux_context() {
    local type="$1"; shift
    command -v selinuxenabled >/dev/null 2>&1 || return 0
    selinuxenabled 2>/dev/null || return 0

    local f
    for f in "$@"; do
        [ -e "$f" ] || continue
        if command -v semanage >/dev/null 2>&1; then
            semanage fcontext -a -t "$type" "$f" >/dev/null 2>&1 \
                || semanage fcontext -m -t "$type" "$f" >/dev/null 2>&1 || true
            restorecon -F "$f" >/dev/null 2>&1 || chcon -t "$type" "$f" >/dev/null 2>&1 || true
        else
            chcon -t "$type" "$f" >/dev/null 2>&1 || true
        fi
    done
}

# ═════════════════════════════════════════════════════════════════════════════
# SERTIFIKAT-HJELPERE OG PINNING
# ═════════════════════════════════════════════════════════════════════════════

cert_fingerprint() {
    openssl x509 -in "$1" -noout -fingerprint -sha256 2>/dev/null \
        | sed 's/.*=//; s/://g' | tr 'A-F' 'a-f'
}

cert_subject() {
    openssl x509 -in "$1" -noout -subject 2>/dev/null | sed 's/^subject=[[:space:]]*//'
}

# Deler en PEM-bundle i enkeltfiler i angitt katalog. Skriver filnavn til stdout.
split_pem_bundle() {
    local bundle="$1" outdir="$2" prefix="${3:-cert-}"
    mkdir -p "$outdir"
    rm -f "$outdir/${prefix}"* 2>/dev/null || true

    "$AWK" -v dir="$outdir" -v pfx="$prefix" '
        /-----BEGIN CERTIFICATE-----/ { n++; f = sprintf("%s/%s%02d.pem", dir, pfx, n) }
        n > 0 { print > f }
        /-----END CERTIFICATE-----/   { if (f != "") close(f) }
    ' "$bundle"

    local f
    for f in "$outdir/${prefix}"*.pem; do
        # Kast bort ufullstendige blokker
        if grep -q 'END CERTIFICATE' "$f" && openssl x509 -in "$f" -noout >/dev/null 2>&1; then
            printf '%s\n' "$f"
        else
            rm -f "$f"
        fi
    done
}

# Kontroller at CA-kjeden vi nettopp lastet ned matcher det vi har sett før.
# Uten dette er nedlastingen ren TOFU hver eneste gang, og en kompromittert
# eller byttet NDES-proxy kan levere en helt annen CA som klienten så stoler
# på for 802.1X-servervalidering.
verify_ca_pins() {
    local chain="$1"
    [ "$CA_PINNING" = true ] || { log_warn "CA-pinning deaktivert"; return 0; }

    local -a current_fps=()
    local f fp
    while IFS= read -r f; do
        fp="$(cert_fingerprint "$f")"
        [ -n "$fp" ] && current_fps+=("$fp")
    done < <(split_pem_bundle "$chain" "$TMP_SPLIT_DIR" "pin-")

    if [ ${#current_fps[@]} -eq 0 ]; then
        log_error "Fant ingen gyldige sertifikater i CA-kjeden"
        return 1
    fi

    if [ ! -f "$PIN_FILE" ] || [ "$UPDATE_PINS" = true ]; then
        if [ -f "$PIN_FILE" ]; then
            log_warn "--update-pins: overskriver eksisterende CA-pins"
        else
            log_warn "Ingen CA-pins fra før — lagrer nåværende (trust on first use)."
            log_warn "Verifiser fingerprintene mot PKI-teamet FØR bred utrulling:"
        fi
        : > "$PIN_FILE"
        chmod 0644 "$PIN_FILE"
        while IFS= read -r f; do
            fp="$(cert_fingerprint "$f")"
            [ -n "$fp" ] || continue
            printf '%s  %s\n' "$fp" "$(cert_subject "$f")" >> "$PIN_FILE"
            log "  PIN $fp  $(cert_subject "$f")"
        done < <(split_pem_bundle "$chain" "$TMP_SPLIT_DIR" "pin-")
        log_success "CA-pins lagret i $PIN_FILE"
        return 0
    fi

    local pinned_fp pinned_subject missing=0
    while read -r pinned_fp pinned_subject; do
        [ -z "$pinned_fp" ] && continue
        case "$pinned_fp" in \#*) continue ;; esac
        local found=false
        for fp in "${current_fps[@]}"; do
            [ "$fp" = "$pinned_fp" ] && { found=true; break; }
        done
        if [ "$found" = false ]; then
            log_error "PIN-BRUDD: forventet CA mangler i nedlastet kjede"
            log_error "  fingerprint: $pinned_fp"
            log_error "  subject:     $pinned_subject"
            missing=$((missing + 1))
        fi
    done < "$PIN_FILE"

    if [ "$missing" -gt 0 ]; then
        log_error "CA-kjeden fra NDES matcher ikke lagrede pins i $PIN_FILE."
        log_error "Dette kan bety CA-fornyelse — ELLER at trafikken manipuleres."
        log_error "Bekreft med PKI-ansvarlig, kjør så på nytt med --update-pins."
        return 1
    fi

    log_success "CA-pinning verifisert mot $PIN_FILE"
    return 0
}

# ═════════════════════════════════════════════════════════════════════════════
# SHA-1-KOMPATIBILITET
# ═════════════════════════════════════════════════════════════════════════════
#
# NDES/SCEP signerer PKCS#7 med SHA-1. Fedora 41+/RHEL 9+ blokkerer dette.
# v3.5.9 løste det med update-crypto-policies --set DEFAULT:SHA1, som svekker
# SHA-1-policy for HELE systemet (SSH, TLS, alt) — permanent, uten rollback.
# Her prøver vi først en drop-in som kun gjelder certmonger-prosessen.

SHA1_DROPIN="/etc/systemd/system/certmonger.service.d/10-sha1-scep-compat.conf"

apply_sha1_scoped() {
    log "Aktiverer SHA-1 kun for certmonger (scoped)"
    mkdir -p "$(dirname "$SHA1_DROPIN")"
    cat > "$SHA1_DROPIN" <<'DROPIN'
# Lagt til av enterprise-network-deploy.sh
# NDES/SCEP signerer PKCS#7 med SHA-1. Denne drop-in tillater SHA-1
# KUN for certmonger-prosessen, i stedet for å svekke systemets
# globale crypto-policy.
[Service]
Environment=OPENSSL_ENABLE_SHA1_SIGNATURES=1
DROPIN
    chmod 0644 "$SHA1_DROPIN"
    record_state "FILE_CREATED:$SHA1_DROPIN"
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl restart certmonger >/dev/null 2>&1 || true
    sleep 3
    log_success "SHA-1 drop-in aktivert for certmonger"
}

apply_sha1_global() {
    command -v update-crypto-policies >/dev/null 2>&1 || {
        log_debug "update-crypto-policies finnes ikke — hopper over"
        return 0
    }
    local current
    current="$(update-crypto-policies --show 2>/dev/null || echo DEFAULT)"
    if [[ "$current" == *SHA1* ]]; then
        log "SHA-1 allerede tillatt i global crypto policy ($current)"
        SHA1_GLOBAL_APPLIED=true
        return 0
    fi
    log_warn "ESKALERER: setter global crypto policy til ${current}:SHA1"
    log_warn "Dette svekker SHA-1-restriksjoner for HELE systemet, ikke bare SCEP."
    if update-crypto-policies --set "${current}:SHA1" >> "$LOG_FILE" 2>&1; then
        record_state "CRYPTO_POLICY_CHANGED:${current}"
        SHA1_GLOBAL_APPLIED=true
        systemctl restart certmonger >/dev/null 2>&1 || true
        sleep 3
        log_success "Global crypto policy: ${current}:SHA1 (rollback registrert)"
    else
        log_error "Klarte ikke sette crypto policy"
        return 1
    fi
}

ensure_sha1_compat() {
    case "$SHA1_MODE" in
        off)
            log "SHA1_MODE=off — ingen SHA-1-tilpasning"
            ;;
        scoped)
            apply_sha1_scoped
            ;;
        global)
            apply_sha1_global
            ;;
        auto)
            apply_sha1_scoped
            # Drop-in med OPENSSL_ENABLE_SHA1_SIGNATURES virker ikke på alle
            # Fedora-utgaver. Den globale policyen er fasiten, men vi venter
            # med å svekke den til vi ser at enrollment faktisk feiler.
            log "SHA1_MODE=auto — eskalerer til global policy hvis enrollment feiler"
            ;;
        *)
            log_error "Ugyldig SHA1_MODE: $SHA1_MODE (auto|scoped|global|off)"
            return 1
            ;;
    esac
    return 0
}

# GetCACert er USIGNERT og lykkes selv når SHA-1 er blokkert. Det er PKCSReq
# — selve sertifikatforespørselen — som er SHA-1-signert. Eskaleringen må
# derfor også kunne utløses fra ventesløyfen under enrollment, ikke bare fra
# nedlastingen. (Dette manglet i 4.0-4.4 og ga CA_UNREACHABLE på Fedora 41+.)
maybe_escalate_sha1() {
    [ "$SHA1_MODE" = "auto" ] || return 1
    [ "$SHA1_GLOBAL_APPLIED" = true ] && return 1
    log_warn "SCEP feilet — mistenker SHA-1-blokkering, eskalerer"
    apply_sha1_global && return 0
    return 1
}

# Skriver ut alt som pleier å forklare en mislykket SCEP-enrollment.
diagnose_scep_failure() {
    local req_id="$1"

    log_section "Diagnostikk"

    log "--- certmonger-forespørsel ---"
    getcert list -i "$req_id" 2>&1 | log_output || true

    log "--- CA-konfigurasjon ---"
    getcert list-cas -c "$CA_NAME" 2>&1 | log_output || true

    log "--- kryptopolicy ---"
    if command -v update-crypto-policies >/dev/null 2>&1; then
        log "  global: $(update-crypto-policies --show 2>/dev/null || echo ukjent)"
    fi
    if [ -f "$SHA1_DROPIN" ]; then
        log "  certmonger drop-in: finnes"
        log "  effektiv env: $(systemctl show certmonger -p Environment --value 2>/dev/null)"
    else
        log "  certmonger drop-in: finnes ikke"
    fi

    log "--- proxy ---"
    # certmonger kjører som systemd-tjeneste og arver IKKE proxy-variabler fra
    # skallet. Nås NDES bare via proxy, feiler helperen med CA_UNREACHABLE selv
    # om den samme URL-en svarer fint fra kommandolinjen.
    local shell_proxy svc_env
    shell_proxy="${https_proxy:-${HTTPS_PROXY:-}}"
    svc_env="$(systemctl show certmonger -p Environment --value 2>/dev/null)"
    if [ -n "$shell_proxy" ]; then
        log "  skallet bruker proxy: $shell_proxy"
        if ! grep -qi 'proxy' <<< "$svc_env"; then
            log_error "  certmonger-tjenesten har INGEN proxy satt."
            log_error "  Det forklarer CA_UNREACHABLE. Legg inn:"
            log_error "    systemctl edit certmonger"
            log_error "    [Service]"
            log_error "    Environment=https_proxy=$shell_proxy"
        fi
    else
        log "  ingen proxy i skallet"
    fi

    log "--- direkte test av SCEP-endepunktet ---"
    local helper
    if helper="$(find_scep_helper)"; then
        if timeout 30 "$helper" -u "$SCEP_URL" -C >/dev/null 2>&1; then
            log "  GetCACert fra dette skallet: OK"
            log "  (endepunktet svarer, så feilen ligger i signering eller i"
            log "   certmonger-tjenestens miljø — ikke i nettverket)"
        else
            log_error "  GetCACert feiler også herfra — nettverk/URL/proxy"
        fi
    fi

    log "--- siste certmonger-logg ---"
    journalctl -u certmonger -n 40 --no-pager 2>&1 | log_output || true

    log "Full logg: $LOG_FILE"
}

# ═════════════════════════════════════════════════════════════════════════════
# AWK-DETEKSJON
# ═════════════════════════════════════════════════════════════════════════════

AWK=""
detect_awk() {
    local c
    for c in gawk awk mawk nawk; do
        if command -v "$c" >/dev/null 2>&1; then
            AWK="$c"
            log_debug "AWK: $AWK"
            return 0
        fi
    done
    log_error "Ingen awk funnet. Installer: dnf install -y gawk  (eller apt-get install -y gawk)"
    return 1
}

# ═════════════════════════════════════════════════════════════════════════════
# SCEP CA-KONFIGURASJON
# ═════════════════════════════════════════════════════════════════════════════

find_scep_helper() {
    local p
    for p in /usr/libexec/certmonger/scep-submit /usr/lib/certmonger/scep-submit \
             /usr/lib64/certmonger/scep-submit; do
        [ -x "$p" ] && { printf '%s\n' "$p"; return 0; }
    done
    return 1
}

download_ca_bundle() {
    local helper="$1"
    local attempt

    for attempt in 1 2; do
        rm -f "$TMP_BUNDLE"

        log "Forsøk $attempt: henter CA-bundle via scep-submit -C"
        if timeout 45 "$helper" -u "$SCEP_URL" -C > "$TMP_BUNDLE" 2>> "$LOG_FILE"; then
            if [ -s "$TMP_BUNDLE" ] && grep -q 'BEGIN CERTIFICATE' "$TMP_BUNDLE"; then
                log_success "CA-bundle hentet via scep-submit"
                return 0
            fi
        fi
        log_warn "scep-submit ga ingen brukbar bundle"

        log "Fallback: GetCACert via HTTPS"
        local p7b="$WORKDIR/ndes-ca.p7b"
        rm -f "$p7b"
        if http_get "${SCEP_URL}?operation=GetCACert&message=CA" "$p7b" && [ -s "$p7b" ]; then
            if openssl pkcs7 -in "$p7b" -inform DER -print_certs -out "$TMP_BUNDLE" 2>> "$LOG_FILE" \
               || openssl pkcs7 -in "$p7b" -inform PEM -print_certs -out "$TMP_BUNDLE" 2>> "$LOG_FILE"; then
                if [ -s "$TMP_BUNDLE" ] && grep -q 'BEGIN CERTIFICATE' "$TMP_BUNDLE"; then
                    log_success "CA-bundle hentet via GetCACert"
                    return 0
                fi
            fi
        fi

        # Første runde feilet — kan skyldes SHA-1-blokkering.
        if [ "$attempt" -eq 1 ]; then
            maybe_escalate_sha1 || break
        fi
    done

    log_error "Klarte ikke hente CA-bundle fra NDES: $SCEP_URL"
    if [ "$ALLOW_INSECURE_TLS" != true ]; then
        log_error "Hvis NDES bruker internt/selvsignert TLS-sert: legg CA-en i systemets"
        log_error "trust store, eller sett ALLOW_INSECURE_TLS=true (frarådes)."
    fi
    return 1
}

# Klassifiser sertifikatene i bundlen: CA-kjede vs RA signing vs RA encryption.
classify_bundle() {
    : > "$TMP_CA_CHAIN"
    : > "$TMP_RA_COMBINED"
    : > "$TMP_RA"
    : > "$TMP_RA_ENC"

    local -a certs=()
    local f
    while IFS= read -r f; do certs+=("$f"); done \
        < <(split_pem_bundle "$TMP_BUNDLE" "$TMP_SPLIT_DIR" "ndes-")

    log "Fant ${#certs[@]} gyldige sertifikat(er) i bundlen"

    if [ ${#certs[@]} -eq 0 ]; then
        log_error "Ingen gyldige sertifikater i bundlen"
        return 1
    fi

    if [ ${#certs[@]} -lt 2 ]; then
        log_warn "Færre enn 2 sertifikater — bruker hele bundlen for både CA og RA"
        cp "$TMP_BUNDLE" "$TMP_CA_CHAIN"
        cp "$TMP_BUNDLE" "$TMP_RA_COMBINED"
        cp "$TMP_BUNDLE" "$TMP_RA"
        cp "$TMP_BUNDLE" "$TMP_RA_ENC"
        return 0
    fi

    local ca_count=0 ra_sign_count=0 ra_enc_count=0
    local cert_text subject is_ca ku has_sign has_enc

    for f in "${certs[@]}"; do
        cert_text="$(openssl x509 -in "$f" -noout -text 2>/dev/null)"
        subject="$(cert_subject "$f")"

        is_ca=false
        if grep -qE 'CA:TRUE|Subject Type=CA' <<< "$cert_text"; then
            is_ca=true
        fi

        if [ "$is_ca" = true ]; then
            cat "$f" >> "$TMP_CA_CHAIN"
            ca_count=$((ca_count + 1))
            log "  CA        -> ca-chain   : $subject"
            continue
        fi

        cat "$f" >> "$TMP_RA_COMBINED"
        ku="$(grep -A1 'X509v3 Key Usage' <<< "$cert_text" | tail -1 | tr -s ' ')"
        has_sign=false; has_enc=false
        grep -qi 'Digital Signature' <<< "$ku" && has_sign=true
        grep -qi 'Key Encipherment'  <<< "$ku" && has_enc=true

        if [ "$has_sign" = false ] && [ "$has_enc" = false ]; then
            cat "$f" >> "$TMP_RA"
            cat "$f" >> "$TMP_RA_ENC"
            ra_sign_count=$((ra_sign_count + 1))
            ra_enc_count=$((ra_enc_count + 1))
            log "  RA(ukjent)-> begge      : $subject"
            continue
        fi

        if [ "$has_enc" = true ]; then
            cat "$f" >> "$TMP_RA_ENC"
            ra_enc_count=$((ra_enc_count + 1))
            log "  RA-enc    -> encryption : $subject"
        fi
        if [ "$has_sign" = true ]; then
            cat "$f" >> "$TMP_RA"
            ra_sign_count=$((ra_sign_count + 1))
            log "  RA-sign   -> signing    : $subject"
        fi
    done

    [ "$ra_enc_count"  -eq 0 ] && { log_warn "Ingen RA encryption-cert — bruker combined"; cp "$TMP_RA_COMBINED" "$TMP_RA_ENC"; }
    [ "$ra_sign_count" -eq 0 ] && { log_warn "Ingen RA signing-cert — bruker combined";    cp "$TMP_RA_COMBINED" "$TMP_RA"; }
    [ "$ca_count"      -eq 0 ] && { log_warn "Ingen CA-sertifikater — bruker hele bundlen"; cp "$TMP_BUNDLE" "$TMP_CA_CHAIN"; }

    log_success "Klassifisering: $ca_count CA, $ra_sign_count RA-sign, $ra_enc_count RA-enc"
    return 0
}

install_ca_material() {
    # Kopier til persistent, SELinux-vennlig sti for certmonger.
    [ -s "$TMP_RA_ENC" ] && install -m 0644 "$TMP_RA_ENC" "$PERM_RA_ENC"
    [ -s "$TMP_RA" ]     && install -m 0644 "$TMP_RA"     "$PERM_RA_SIGN"
    install -m 0644 "$TMP_CA_CHAIN" "$PERM_CA_CHAIN"

    # Finn Enterprise/utstedende CA for -N-flagget.
    : > "$PERM_ENTERPRISE_CA"
    chmod 0644 "$PERM_ENTERPRISE_CA"
    local f
    while IFS= read -r f; do
        if cert_subject "$f" | grep -qi 'Enterprise'; then
            cat "$f" > "$PERM_ENTERPRISE_CA"
            log "Enterprise CA valgt for -N: $(cert_subject "$f")"
        fi
    done < <(split_pem_bundle "$TMP_CA_CHAIN" "$TMP_SPLIT_DIR" "cachain-")

    if [ ! -s "$PERM_ENTERPRISE_CA" ]; then
        log_warn "Fant ingen 'Enterprise' CA — bruker hele CA-kjeden for -N"
        cp "$TMP_CA_CHAIN" "$PERM_ENTERPRISE_CA"
    fi

    cat "$TMP_RA" "$TMP_RA_ENC" "$TMP_CA_CHAIN" > "$PERM_ALL_CERTS" 2>/dev/null
    chmod 0644 "$PERM_ALL_CERTS"

    set_selinux_context certmonger_var_lib_t \
        "$PERM_RA_ENC" "$PERM_RA_SIGN" "$PERM_CA_CHAIN" \
        "$PERM_ENTERPRISE_CA" "$PERM_ALL_CERTS"

    # Trust store: KUN CA-kjeden. v3.5.9 la også RA-sertifikatet inn som
    # trust anchor — et endepunkt-sertifikat hører ikke hjemme der.
    if [ "$INSTALL_CA_IN_TRUST_STORE" = true ]; then
        if [ -d /etc/pki/ca-trust/source/anchors ]; then
            install -m 0644 "$TMP_CA_CHAIN" /etc/pki/ca-trust/source/anchors/ndes-ca-chain.crt
            rm -f /etc/pki/ca-trust/source/anchors/ndes-ra.crt   # rydd opp etter v3.5.x
            update-ca-trust extract >> "$LOG_FILE" 2>&1
            log_success "CA-kjede installert i trust store (RHEL-familien)"
        elif [ -d /usr/local/share/ca-certificates ]; then
            install -m 0644 "$TMP_CA_CHAIN" /usr/local/share/ca-certificates/ndes-ca-chain.crt
            rm -f /usr/local/share/ca-certificates/ndes-ra.crt
            update-ca-certificates >> "$LOG_FILE" 2>&1
            log_success "CA-kjede installert i trust store (Debian/Ubuntu)"
        else
            log_warn "Fant ingen kjent trust store-katalog"
        fi
        # Bundlen kan ha endret seg — finn den på nytt.
        detect_system_ca_bundle || true
    else
        log "INSTALL_CA_IN_TRUST_STORE=false — hopper over systemets trust store"
    fi

    log_success "Persistente CA-filer lagret i $CERTMONGER_CERT_DIR"
}

scep_helper_supports_flags() {
    local helper="$1"
    local ver major minor
    ver="$(rpm -q --qf '%{VERSION}' certmonger 2>/dev/null)" || ver=""
    if [ -z "$ver" ] && command -v dpkg-query >/dev/null 2>&1; then
        ver="$(dpkg-query -W -f='${Version}' certmonger 2>/dev/null || true)"
    fi
    ver="${ver#*:}"
    major="${ver%%.*}"
    minor="${ver#*.}"; minor="${minor%%.*}"

    if [[ "$major" =~ ^[0-9]+$ ]] && [[ "$minor" =~ ^[0-9]+$ ]]; then
        if [ "$major" -gt 0 ] || [ "$minor" -ge 79 ]; then
            return 0
        fi
        return 1
    fi
    # Ukjent versjon — spør hjelperen direkte.
    "$helper" -h 2>&1 | grep -q -- '-R' && return 0
    return 1
}

configure_scep_ca() {
    log "Konfigurerer SCEP CA: $CA_NAME"

    local helper
    helper="$(find_scep_helper)" || {
        log_error "Fant ikke scep-submit. Installer certmonger."
        return 1
    }
    log "SCEP-helper: $helper"

    if getcert list-cas 2>/dev/null | grep -q "^CA '$CA_NAME'"; then
        log "Fjerner eksisterende CA-konfigurasjon"
        getcert remove-ca -c "$CA_NAME" >/dev/null 2>&1 || true
        sleep 2
    fi

    log "--- Steg 1: hent CA-bundle ---"
    download_ca_bundle "$helper" || return 1

    log "--- Steg 2: klassifiser CA/RA ---"
    classify_bundle || return 1

    log "--- Steg 3: verifiser CA-pinning ---"
    verify_ca_pins "$TMP_CA_CHAIN" || return 1

    log "--- Steg 4: installer CA-materiale ---"
    install_ca_material

    log "--- Steg 5: registrer CA i certmonger ---"
    [ -n "$SYSTEM_CA_BUNDLE" ] || detect_system_ca_bundle || return 1

    local -a helper_args=(-u "$SCEP_URL")
    if scep_helper_supports_flags "$helper"; then
        helper_args+=(-R "$SYSTEM_CA_BUNDLE")
        [ -s "$PERM_ENTERPRISE_CA" ] && helper_args+=(-N "$PERM_ENTERPRISE_CA")
        [ -s "$PERM_ALL_CERTS" ]     && helper_args+=(-I "$PERM_ALL_CERTS")
        log_debug "scep-submit støtter -R/-N/-I"
    else
        log_warn "Eldre certmonger — kun -u støttes av hjelperen"
    fi

    local out
    out="$(getcert add-scep-ca -c "$CA_NAME" -u "$SCEP_URL" -R "$SYSTEM_CA_BUNDLE" 2>&1)"
    printf '%s\n' "$out" >> "$LOG_FILE"
    log_debug "add-scep-ca: $out"

    sleep 3
    if ! getcert list-cas 2>/dev/null | grep -q "^CA '$CA_NAME'"; then
        log_error "getcert add-scep-ca feilet: $out"
        return 1
    fi
    record_state "CA_ADDED:$CA_NAME"
    log_success "CA '$CA_NAME' registrert"

    # Oppdater certmongers interne config med -N/-I. Merk: ca_encryption_cert
    # settes bevisst IKKE — certmonger 0.79+ henter RA-encryption-cert dynamisk,
    # og manuell verdi gir "Error decrypting PKCS#7" / NEED_GUIDANCE.
    local ca_config
    ca_config="$(grep -l "^id=$CA_NAME$" "${CERTMONGER_CERT_DIR}"/cas/* 2>/dev/null | head -1)"
    if [ -z "$ca_config" ]; then
        ca_config="$(grep -l "id=$CA_NAME" "${CERTMONGER_CERT_DIR}"/cas/* 2>/dev/null | head -1)"
    fi
    if [ -z "$ca_config" ]; then
        log_error "Fant ikke certmongers CA-configfil for $CA_NAME"
        return 1
    fi

    log "Oppdaterer certmonger-config: $ca_config"
    backup_for_rollback "$ca_config"
    record_state "SERVICE_STATE:certmonger"

    systemctl stop certmonger >/dev/null 2>&1 || true
    sleep 2

    local helper_cmdline="$helper"
    local a
    for a in "${helper_args[@]}"; do
        helper_cmdline+=" $(printf '%q' "$a")"
    done

    {
        printf 'id=%s\n' "$CA_NAME"
        printf 'ca_aka=SCEP (enterprise-network-deploy %s)\n' "$SCRIPT_VERSION"
        printf 'ca_is_default=0\n'
        printf 'ca_type=EXTERNAL\n'
        printf 'ca_external_helper=%s\n' "$helper_cmdline"
    } > "$ca_config"
    chmod 0600 "$ca_config"
    set_selinux_context certmonger_var_lib_t "$ca_config"

    systemctl start certmonger >/dev/null 2>&1
    for _ in $(seq 1 20); do
        systemctl is-active --quiet certmonger && break
        sleep 1
    done
    sleep 2

    if ! getcert list-cas 2>/dev/null | grep -q "^CA '$CA_NAME'"; then
        log_error "Certmonger mistet CA-config etter restart"
        return 1
    fi

    getcert list-cas -c "$CA_NAME" >> "$LOG_FILE" 2>&1 || true
    log_success "SCEP CA konfigurert (dynamisk RA-cert, TLS via system-CA)"
    return 0
}

# ═════════════════════════════════════════════════════════════════════════════
# VPN-KLIENTPAKKE  (FortiClient m.fl.)
# ═════════════════════════════════════════════════════════════════════════════
#
# Bygger en PKCS#12 av maskin-sertifikatet og legger inn eventuelle ekstra
# trust anchors. Kjører uavhengig av om FortiClient faktisk er installert —
# pakka ligger da klar til import når klienten kommer på plass.

# Finn brukeren som skal eie .p12-fila.
# Finner katalogen .p12 skal ligge i. xdg-user-dir kjøres SOM brukeren, ellers
# får vi root sine kataloger. Faller tilbake til hjemmekatalogen hvis
# skrivebordsmappa ikke finnes (headless, minimal install).
# Importerer .p12 i brukerens NSS-database. Kjøres SOM brukeren, ellers havner
# alt i root sin database.
import_p12_to_nssdb() {
    local user="$1" home="$2" p12="$3" pass="$4"

    [ "$P12_IMPORT_NSS" = true ] || return 0
    [ -n "$user" ] || { log_debug "Ingen målbruker — hopper over NSS-import"; return 0; }

    if ! command -v pk12util >/dev/null 2>&1; then
        log_warn "pk12util mangler — hopper over NSS-import"
        log_warn "  Installer med: dnf install -y nss-tools"
        return 0
    fi

    local db="${home}/.pki/nssdb"
    if [ ! -d "$db" ]; then
        log "Oppretter NSS-database: $db"
        runuser -u "$user" -- mkdir -p "$db" 2>/dev/null || {
            log_warn "Klarte ikke opprette $db"
            return 0
        }
        runuser -u "$user" -- certutil -d "sql:$db" -N --empty-password >> "$LOG_FILE" 2>&1 || {
            log_warn "Klarte ikke initialisere NSS-databasen"
            return 0
        }
    fi

    # Allerede importert? Unngå duplikater ved hver kjøring.
    if runuser -u "$user" -- certutil -d "sql:$db" -L 2>/dev/null \
         | grep -Fq "$P12_FRIENDLY_NAME"; then
        log "Sertifikatet finnes allerede i brukerens NSS-database"
        return 0
    fi

    # Passordet sendes via fil, ikke som argument (synlig i ps).
    local pf="$WORKDIR/nss.pass"
    ( umask 077; printf '%s' "$pass" > "$pf" )
    chown "$user" "$pf" 2>/dev/null || true

    if runuser -u "$user" -- pk12util -i "$p12" -d "sql:$db" -w "$pf" >> "$LOG_FILE" 2>&1; then
        log_success "Importert i brukerens NSS-database ($db)"
        log "  Vises i FortiClient hvis klienten leser derfra."
    else
        log_warn "NSS-import feilet — bruker må importere .p12 manuelt"
    fi
    rm -f "$pf"
    return 0
}

resolve_p12_dir() {
    local user="$1" home="$2"
    local sub="${P12_TARGET_SUBDIR:-}"

    [ -z "$sub" ] && { printf '%s\n' "$home"; return 0; }

    # Nøkkelord -> XDG-oppslag. xdg-user-dir kjøres SOM brukeren, ellers får vi
    # root sine kataloger.
    case "$sub" in
        DESKTOP|DOWNLOAD|DOCUMENTS|PUBLICSHARE|TEMPLATES)
            local dir=""
            if command -v xdg-user-dir >/dev/null 2>&1; then
                dir="$(runuser -u "$user" -- xdg-user-dir "$sub" 2>/dev/null || true)"
            fi
            if [ -n "$dir" ] && [ -d "$dir" ] && [ "$dir" != "$home" ]; then
                printf '%s\n' "$dir"
                return 0
            fi
            local candidate
            for candidate in Desktop Skrivebord Skrivbord Downloads Nedlastinger; do
                if [ -d "${home}/${candidate}" ]; then
                    printf '%s\n' "${home}/${candidate}"
                    return 0
                fi
            done
            printf '%s\n' "$home"
            return 0
            ;;
    esac

    # Vanlig relativ sti. Absolutte stier og .. avvises — verdien kommer fra
    # konfig, men fila skrives som root i en brukers hjemmekatalog.
    case "$sub" in
        /*|*..*)
            log_warn "Ugyldig P12_TARGET_SUBDIR ($sub) — bruker hjemmekatalogen"
            printf '%s\n' "$home"
            return 0
            ;;
    esac

    printf '%s/%s\n' "$home" "${sub#./}"
    return 0
}

# Domenebruker = finnes (getent), men står ikke i den lokale passwd-fila.
# AD-brukere via SSSD/realmd er det; lokale kontoer fra imaget er det ikke.
is_domain_user() {
    local u="$1"
    getent passwd "$u" >/dev/null 2>&1 || return 1
    [ -r "$LOCAL_PASSWD_FILE" ] || return 1
    ! "$AWK" -F: -v u="$u" '$1 == u { f = 1 } END { exit !f }' "$LOCAL_PASSWD_FILE"
}

is_excluded_user() {
    local u="$1" x
    for x in $P12_EXCLUDE_USERS; do
        [ "$x" = "$u" ] && return 0
    done
    return 1
}

remember_p12_user() {
    local u="$1" prev=""
    [ -s "$P12_TARGET_USER_FILE" ] && prev="$(head -1 "$P12_TARGET_USER_FILE" | tr -d '[:space:]')"
    [ "$prev" = "$u" ] && return 0
    install -d -m 0700 "$(dirname "$P12_TARGET_USER_FILE")" 2>/dev/null || true
    [ -e "$P12_TARGET_USER_FILE" ] || record_state "FILE_CREATED:$P12_TARGET_USER_FILE"
    ( umask 022; printf '%s\n' "$u" > "$P12_TARGET_USER_FILE" )
    log "Husker sluttbruker for .p12: $u ($P12_TARGET_USER_FILE)"
}

# Fjerner .p12 som skriptet har lagt hos andre brukere enn målbrukeren —
# nøyaktig skriptets sti, ingenting annet. Typisk teknikerens konto etter en
# kjøring der feil bruker ble valgt.
remove_p12_from_other_users() {
    local keep="$1" d o f dir removed=0
    for d in /home/*/; do
        d="${d%/}"
        [ -d "$d" ] || continue
        o="$(stat -c '%U' "$d" 2>/dev/null)"
        [ "$o" = "$keep" ] && continue
        dir="$(resolve_p12_dir "$o" "$d")"
        f="${dir}/${P12_FILENAME}"
        [ -f "$f" ] || continue
        shred -u "$f" 2>/dev/null || rm -f "$f"
        rm -f "${dir}/LES-MEG.txt"
        rmdir "$dir" 2>/dev/null && rmdir "$(dirname "$dir")" 2>/dev/null || true
        log_warn "Fjernet .p12 hos annen bruker ($o): $f"
        removed=$((removed + 1))
    done
    [ "$removed" -gt 0 ] && log_success "Maskinnøkkelen ligger nå bare hos $keep"
    return 0
}

# Vanlige brukere på maskinen. Leser eierne av katalogene i /home i stedet
# for å telle opp passwd: AD-/SSSD-brukere (sal o.l.) har UID langt over
# 65534 og kommer ikke med i "getent passwd" uten enumerering.
list_human_users() {
    {
        local d o uid h
        # /home/<bruker> (vanlig, og SSSD /home/%u@%d) og /home/<domene>/<bruker>
        # (SSSD fallback_homedir=/home/%d/%u). Bare kataloger som ER brukerens
        # hjemmekatalog ifølge getent teller — undermapper som Skrivebord faller bort.
        for d in /home/*/ /home/*/*/; do
            d="${d%/}"
            [ -d "$d" ] || continue
            o="$(stat -c '%U' "$d" 2>/dev/null)"
            uid="$(stat -c '%u' "$d" 2>/dev/null)"
            [ -n "$o" ] && [ "$o" != "UNKNOWN" ] && [ "$o" != "root" ] || continue
            [[ "$uid" =~ ^[0-9]+$ ]] && [ "$uid" -ge 1000 ] && [ "$uid" -ne 65534 ] || continue
            h="$(getent passwd "$o" 2>/dev/null | cut -d: -f6)"
            [ "$h" = "$d" ] && printf '%s\n' "$o"
        done
        if command -v loginctl >/dev/null 2>&1; then
            loginctl list-users --no-legend 2>/dev/null \
                | "$AWK" '$1 ~ /^[0-9]+$/ && $1 >= 1000 && $1 != 65534 && $2 != "root" {print $2}'
        fi
    } | sort -u | while IFS= read -r u; do
        is_excluded_user "$u" || printf '%s\n' "$u"
    done
}

# Eieren av den aktive, lokale, grafiske sesjonen på maskinen — personen som
# sitter foran skjermen. Ikke "første sesjon i lista", som var 4.15-logikken.
active_graphical_user() {
    command -v loginctl >/dev/null 2>&1 || return 1
    local sid props u
    for sid in $(loginctl list-sessions --no-legend 2>/dev/null | "$AWK" '{print $1}'); do
        props="$(loginctl show-session "$sid" -p Name -p Type -p Class -p Active -p Remote 2>/dev/null)"
        grep -qx 'Class=user'  <<< "$props" || continue
        grep -qx 'Active=yes'  <<< "$props" || continue
        grep -qx 'Remote=no'   <<< "$props" || continue
        grep -qxE 'Type=(x11|wayland)' <<< "$props" || continue
        u="$(sed -n 's/^Name=//p' <<< "$props")"
        [ -n "$u" ] && [ "$u" != "root" ] && { printf '%s\n' "$u"; return 0; }
    done
    return 1
}

# Interaktivt valg når flere brukere er mulige. Leser og skriver /dev/tty,
# så det virker også inne i $( ).
prompt_p12_user() {
    local guess="$1"; shift
    local -a cands=("$@")
    local i ans pick tries=0
    # Bevisst INGEN standardverdi: gjetningen er ofte teknikeren som kjører
    # sudo, og "bare trykk Enter" ville gjentatt feilen fra 4.15.
    {
        printf '\n'
        printf 'Flere brukere på maskinen kan få VPN-sertifikatet (.p12):\n'
        for i in "${!cands[@]}"; do
            if [ "${cands[$i]}" = "$guess" ]; then
                printf '  %d) %s   (kjører skriptet nå)\n' "$((i + 1))" "${cands[$i]}"
            else
                printf '  %d) %s\n' "$((i + 1))" "${cands[$i]}"
            fi
        done
        printf 'Velg SLUTTBRUKEREN — den som skal bruke FortiClient, ikke nødvendigvis deg.\n'
    } > /dev/tty
    while [ "$tries" -lt 3 ]; do
        tries=$((tries + 1))
        printf 'Nummer eller brukernavn: ' > /dev/tty
        IFS= read -r ans < /dev/tty || return 1
        ans="${ans//[[:space:]]/}"
        pick=""
        if [ -z "$ans" ]; then
            printf 'Velg en bruker (ingen standard).\n' > /dev/tty
            continue
        elif [[ "$ans" =~ ^[0-9]+$ ]] && [ "$ans" -ge 1 ] && [ "$ans" -le "${#cands[@]}" ]; then
            pick="${cands[$((ans - 1))]}"
        elif getent passwd "$ans" >/dev/null 2>&1; then
            pick="$ans"
        fi
        if [ -n "$pick" ]; then
            printf '%s\n' "$pick"
            return 0
        fi
        printf 'Ukjent bruker: %s\n' "$ans" > /dev/tty
    done
    return 1
}

can_prompt() {
    [ "$TEST_MODE" = false ] || return 1
    [ -t 0 ] || return 1
    { : > /dev/tty; } 2>/dev/null
}

# Finner hvilken bruker .p12 skal tilhøre.
#
# Skriver "bruker|begrunnelse|lagre" (lagre = 1 når valget er sikkert nok til
# å huskes), eller "|begrunnelse|0" og returnerer 1 når ingen bruker velges.
# MERK: kalles inne i $( ) — skriver KUN resultatlinja til stdout.
#
# Rekkefølge:
#   1. eksplisitt: --user <navn> eller P12_TARGET_USER=<navn>
#   2. valget fra forrige gang (P12_TARGET_USER_FILE)
#   3. gjetning: SUDO_USER -> logname -> aktiv grafisk sesjon -> eneste bruker
#   4. er flere brukere mulige: spør (interaktivt), ellers ingen bruker
#      (systemvidt) + advarsel. 4.15 tok her bare første innloggede sesjon,
#      og la maskinnøkkelen hos teknikeren i stedet for sluttbrukeren.
resolve_p12_user() {
    local u="${P12_TARGET_USER:-}"

    # Tom verdi = bevisst systemsti.
    [ -z "$u" ] && { printf '||0\n'; return 1; }

    if [ "$u" != "auto" ]; then
        if getent passwd "$u" >/dev/null 2>&1; then
            printf '%s|angitt eksplisitt|1\n' "$u"
            return 0
        fi
        printf '|FEIL: bruker "%s" finnes ikke på maskinen|0\n' "$u"
        return 1
    fi

    # 2. Valget fra forrige gang
    if [ -s "$P12_TARGET_USER_FILE" ]; then
        local saved
        saved="$(head -1 "$P12_TARGET_USER_FILE" | tr -d '[:space:]')"
        if [ -n "$saved" ] && ! is_excluded_user "$saved" \
           && getent passwd "$saved" >/dev/null 2>&1; then
            printf '%s|valgt tidligere, lagret i %s|0\n' "$saved" "$P12_TARGET_USER_FILE"
            return 0
        fi
    fi

    # 3. Gjetning
    local guess="" why="" c
    c="${SUDO_USER:-}"
    if [ -n "$c" ] && [ "$c" != "root" ] && getent passwd "$c" >/dev/null 2>&1; then
        guess="$c"; why="kjørte sudo"
    fi
    if [ -z "$guess" ]; then
        c="$(logname 2>/dev/null || true)"
        if [ -n "$c" ] && [ "$c" != "root" ] && getent passwd "$c" >/dev/null 2>&1; then
            guess="$c"; why="innlogget på konsollet"
        fi
    fi
    if [ -z "$guess" ] && c="$(active_graphical_user)"; then
        guess="$c"; why="sitter ved skjermen (aktiv grafisk sesjon)"
    fi
    if [ -n "$guess" ] && is_excluded_user "$guess"; then
        guess=""; why=""
    fi

    # 4. Hvor mange brukere er mulige?
    local -a cands=()
    local line
    while IFS= read -r line; do
        [ -n "$line" ] && cands+=("$line")
    done < <( { list_human_users; [ -n "$guess" ] && printf '%s\n' "$guess"; } | sort -u )

    if [ "${#cands[@]}" -eq 0 ]; then
        printf '|ingen vanlige brukere finnes ennå|0\n'
        return 1
    fi

    if [ "${#cands[@]}" -eq 1 ]; then
        if [ -z "$guess" ]; then
            if [ -n "$P12_EXCLUDE_USERS" ]; then
                printf '%s|eneste bruker utenom utelatte (%s)|1\n' "${cands[0]}" "$P12_EXCLUDE_USERS"
            else
                printf '%s|eneste bruker på maskinen|1\n' "${cands[0]}"
            fi
        else
            printf '%s|%s, og eneste bruker på maskinen|1\n' "$guess" "$why"
        fi
        return 0
    fi

    # Flere mulige. Personen som kjører sudo er ofte teknikeren, ikke den som
    # skal bruke VPN — derfor gjettes det ikke på det. Men to signaler er
    # entydige nok til å velge automatisk, også fra ManageEngine:
    #   1. nøyaktig én DOMENEBRUKER blant kandidatene (resten er lokale)
    #   2. nøyaktig én kandidat SITTER VED SKJERMEN (aktiv grafisk sesjon)
    local -a dom=() act=()
    local active
    active="$(active_graphical_user 2>/dev/null || true)"
    for c in "${cands[@]}"; do
        is_domain_user "$c" && dom+=("$c")
        [ -n "$active" ] && [ "$c" = "$active" ] && act+=("$c")
    done
    if [ "${#dom[@]}" -eq 1 ]; then
        printf '%s|eneste domenebruker (AD) — de andre er lokale kontoer|1\n' "${dom[0]}"
        return 0
    fi
    if [ "${#act[@]}" -eq 1 ]; then
        printf '%s|sitter ved skjermen (aktiv grafisk sesjon)|1\n' "${act[0]}"
        return 0
    fi

    if can_prompt; then
        local pick
        local runner=""
        [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ] && runner="$SUDO_USER"
        if pick="$(prompt_p12_user "$runner" "${cands[@]}")"; then
            printf '%s|valgt interaktivt|1\n' "$pick"
            return 0
        fi
    fi

    local list
    list="$(printf '%s, ' "${cands[@]}")"; list="${list%, }"
    printf '|flere mulige brukere (%s) — angi med --user <navn>|0\n' "$list"
    return 1
}

# Installer en ekstra trust anchor (typisk et mellomliggende CA som VPN-gatewayen
# ikke sender med i handshaken).
#
# To krav, begge fraværende i kollegaens versjon:
#   1) HTTPS. Originalen hentet over http:// og installerte resultatet som
#      trust anchor — en MITM kunne dermed plante et vilkårlig rot-CA.
#   2) Kjeden må validere mot systemets EKSISTERENDE trust store. Da kan en
#      angriper ikke bytte inn et selvsignert CA uansett transport: enten
#      kjeder sertifikatet til noe vi allerede stoler på, eller så avvises det.
install_extra_anchor() {
    local spec="$1"
    local url="${spec%%|*}"
    local pin=""
    [ "$spec" != "$url" ] && pin="${spec#*|}"

    local name
    name="$(basename "${url%%\?*}")"
    name="${name%.crt}"; name="${name%.pem}"; name="${name%.cer}"
    name="$(printf '%s' "$name" | tr -c 'A-Za-z0-9._-' '_')"
    [ -n "$name" ] || name="extra-anchor"

    case "$url" in
        https://*) : ;;
        http://*)
            # Kjedevalideringen er integritetskontrollen, ikke transporten:
            # et innsatt sertifikat vil ikke validere mot trust store og blir
            # avvist lenger nede. AIA-URLer er http per RFC 5280.
            if [ "$EXTRA_ANCHOR_REQUIRE_CHAIN" = true ] || [ "$ALLOW_INSECURE_TLS" = true ]; then
                log "Henter over HTTP (integritet sikres av kjedevalidering): $url"
            else
                log_error "HTTP krever at EXTRA_ANCHOR_REQUIRE_CHAIN=true: $url"
                return 1
            fi
            ;;
        *)
            log_error "Ugyldig anchor-URL: $url"
            return 1
            ;;
    esac

    local raw="$WORKDIR/anchor-${name}.raw"
    local pem="$WORKDIR/anchor-${name}.pem"

    log "Henter trust anchor: $url"
    if [[ "$url" == http://* ]]; then
        curl -fsSL --connect-timeout 15 --max-time 60 --retry 2 -o "$raw" "$url" 2>> "$LOG_FILE" \
            || { log_error "Nedlasting feilet: $url"; return 1; }
    else
        http_get "$url" "$raw" || { log_error "Nedlasting feilet: $url"; return 1; }
    fi

    # DER eller PEM
    if ! openssl x509 -in "$raw" -inform DER -out "$pem" 2>/dev/null; then
        if ! openssl x509 -in "$raw" -inform PEM -out "$pem" 2>/dev/null; then
            log_error "Nedlastet fil er ikke et gyldig sertifikat: $url"
            return 1
        fi
    fi

    local fp subj
    fp="$(cert_fingerprint "$pem")"
    subj="$(cert_subject "$pem")"
    log "  Subject:     $subj"
    log "  SHA256:      $fp"

    if [ -n "$pin" ]; then
        local pin_norm
        pin_norm="$(printf '%s' "$pin" | tr -d ': \n' | tr 'A-F' 'a-f')"
        if [ "$fp" != "$pin_norm" ]; then
            log_error "Fingerprint stemmer ikke med pin for $name"
            log_error "  forventet: $pin_norm"
            log_error "  fikk:      $fp"
            return 1
        fi
        log_success "  Fingerprint matcher pin"
    fi

    # Må kjede til noe vi allerede stoler på — ELLER være eksplisitt pinnet.
    # Pin er et fullgodt alternativ: da har et menneske bestemt nøyaktig hvilket
    # sertifikat som skal inn, og nedlastingen kan ikke byttes ut i det stille.
    # Dette er tilfellet når rota er fjernet fra distroens trust store, slik som
    # DigiCert Global Root CA (G1) fra og med 2026.
    if openssl verify -CAfile "$SYSTEM_CA_BUNDLE" "$pem" >/dev/null 2>&1; then
        log_success "  Validerer mot systemets trust store"
    elif openssl verify -CAfile "$SYSTEM_CA_BUNDLE" -partial_chain "$pem" >/dev/null 2>&1; then
        log_success "  Validerer mot systemets trust store (partial chain)"
    elif [ -n "$pin" ]; then
        log_warn "  Kjeder ikke til kjent rot, men fingerprint er eksplisitt pinnet."
        log_warn "  Utsteder: $(openssl x509 -in "$pem" -noout -issuer 2>/dev/null | sed 's/^issuer=[[:space:]]*//')"
        log_warn "  Sjekk om rot-CA-en er fjernet fra distroen (utgått/distrustet)."
    else
        if [ "$EXTRA_ANCHOR_REQUIRE_CHAIN" = true ]; then
            log_error "Sertifikatet kjeder ikke til noe systemet allerede stoler på."
            log_error "Nekter å installere det som trust anchor: $subj"
            log_error "Legg på en fingerprint-pin (\"URL|<sha256>\") for å godkjenne det"
            log_error "bevisst, eller sett EXTRA_ANCHOR_REQUIRE_CHAIN=false."
            log_error "Fingerprint på det som ble hentet nå: $fp"
            return 1
        fi
        log_warn "  Kjeder ikke til kjent rot — installeres likevel (overstyrt)"
    fi

    place_ca_cert "$pem" "$name" || return 1
    if [ "$PLACED_AS" = "chain-only" ]; then
        log_success "Mellom-CA installert for kjedebygging: $name"
        log "  Ikke et tillitsanker — tilliten kommer fortsatt fra rot-CA-en."
    else
        log_success "Trust anchor installert: $name"
    fi
    return 0
}

# MERK: generate_p12_password kalles inne i $( ), så den skal skrive KUN
# passordet til stdout. All logging som går til stdout (log/log_warn/
# log_success) ville ellers havnet midt i passordet. Advarsler hører derfor
# hjemme her, ikke der.
validate_p12_password_mode() {
    case "$P12_PASSWORD_MODE" in
        fixed)
            if [ "${#P12_PASSWORD}" -lt 12 ] && [ -n "$P12_PASSWORD" ]; then
                log_warn "Fast p12-passord er kort (${#P12_PASSWORD} tegn) og likt på alle maskiner."
                log_warn "Greit som ren transportkode, forutsatt at fila ryddes bort etter import"
                log_warn "(P12_RETENTION_DAYS=$P12_RETENTION_DAYS) og ikke ligger i en katalog som"
                log_warn "synkroniseres eller tas backup av."
            fi
            ;;
        env)
            log_warn "P12_PASSWORD_MODE=env: passordet er synlig i /proc for andre prosesser"
            ;;
    esac
    return 0
}

# Passordet som en ALLEREDE BYGGET .p12 skal kunne åpnes med.
# Skiller seg fra generate_p12_password i random-modus: der ville et nytt kall
# gitt en ny tilfeldig verdi, mens fila på disk har den lagrede.
current_p12_password() {
    case "$P12_PASSWORD_MODE" in
        fixed) printf '%s' "$P12_PASSWORD" ;;
        env)   printf '%s' "${P12_PASS:-}" ;;
        *)     [ -s "$P12_PASSWORD_FILE" ] && tr -d '\n' < "$P12_PASSWORD_FILE" ;;
    esac
}

generate_p12_password() {
    case "$P12_PASSWORD_MODE" in
        fixed)
            if [ -z "$P12_PASSWORD" ]; then
                log_error "P12_PASSWORD_MODE=fixed, men P12_PASSWORD er ikke satt"
                return 1
            fi
            printf '%s' "$P12_PASSWORD"
            ;;
        env)
            if [ -z "${P12_PASS:-}" ]; then
                log_error "P12_PASSWORD_MODE=env, men P12_PASS er ikke satt"
                return 1
            fi
            printf '%s' "$P12_PASS"
            ;;
        file)
            if [ ! -s "$P12_PASSWORD_FILE" ]; then
                log_error "P12_PASSWORD_MODE=file, men $P12_PASSWORD_FILE er tom/mangler"
                return 1
            fi
            head -c 512 "$P12_PASSWORD_FILE" | tr -d '\n'
            ;;
        random|*)
            # 128 bit entropi, kun tegn som overlever copy/paste i GUI-dialoger.
            openssl rand -base64 24 | tr -d '\n=+/' | cut -c1-22
            ;;
    esac
}

build_machine_p12() {
    local target_user="$1" target_path="$2"

    if [ ! -s "$MACHINE_CERT" ] || [ ! -s "$MACHINE_KEY" ]; then
        log_warn "Maskin-sertifikat/nøkkel mangler ennå — hopper over .p12"
        log_warn "Kjør skriptet på nytt når certmonger har fått sertifikatet."
        return 2
    fi

    # Ikke pakk en nøkkel og et sertifikat som ikke hører sammen.
    local c_mod k_mod
    c_mod="$(openssl x509 -in "$MACHINE_CERT" -noout -pubkey 2>/dev/null | openssl sha256 | "$AWK" '{print $NF}')"
    k_mod="$(openssl pkey -in "$MACHINE_KEY" -pubout 2>/dev/null | openssl sha256 | "$AWK" '{print $NF}')"
    if [ -z "$c_mod" ] || [ "$c_mod" != "$k_mod" ]; then
        log_error "Privatnøkkelen matcher ikke sertifikatet — avbryter .p12-bygging"
        return 1
    fi
    log_success "Nøkkel og sertifikat hører sammen"

    # Idempotens: ikke bygg om en pakke som allerede matcher sertifikatet.
    local cur_fp prev_fp=""
    cur_fp="$(cert_fingerprint "$MACHINE_CERT")"
    [ -s "$P12_FP_MARKER" ] && prev_fp="$(tr -d '\n' < "$P12_FP_MARKER")"
    if [ "$FORCE_P12" = false ] && [ -n "$cur_fp" ] && [ "$cur_fp" = "$prev_fp" ]; then
        # Sertifikatet alene er ikke nok. Har passordmodus eller passord endret
        # seg siden fila ble laget (f.eks. random -> fixed), ligger den der med
        # et passord brukeren ikke har fått. Test at den faktisk lar seg åpne
        # med passordet som gjelder nå.
        local existing_pw
        existing_pw="$(current_p12_password)"
        if [ -s "$target_path" ] && [ -n "$existing_pw" ] \
           && ! openssl pkcs12 -in "$target_path" -noout \
                 -passin "pass:$existing_pw" >/dev/null 2>&1; then
            log_warn "Eksisterende .p12 lar seg ikke åpne med gjeldende passord"
            log_warn "  (passordmodus er trolig endret) — bygger på nytt"
            rm -f "$target_path"
        fi

        if [ -s "$target_path" ]; then
            # Vis HVA som beholdes, ikke bare at noe ble hoppet over — ellers
            # ser det ut som skriptet ikke gjorde jobben sin.
            log_success "PKCS#12 er allerede i synk med sertifikatet — beholdes"
            log "  fil:      $target_path"
            log "  laget:    $(date -r "$target_path" '+%Y-%m-%d %H:%M' 2>/dev/null)"
            log "  sertifikat sha256: $cur_fp"
            log "  (bygg om med: --vpn-bundle-only --force-p12)"
            return 0
        fi
        # Fila er borte, men fingerprinten stemmer: den er levert og ryddet
        # bort med vilje. Ikke legg maskinnøkkelen ut på nytt uoppfordret.
        if [ -f "$P12_DELIVERED_MARKER" ]; then
            log "PKCS#12 er allerede levert for dette sertifikatet og ryddet bort"
            log "  (kjør med --force-p12 hvis den skal lages på nytt)"
            return 0
        fi
    fi

    local passfile="$WORKDIR/p12.pass"
    local pass
    validate_p12_password_mode
    pass="$(generate_p12_password)" || return 1
    if [ -z "$pass" ]; then
        log_error "Fikk tomt PKCS#12-passord — avbryter"
        return 1
    fi
    ( umask 077; printf '%s' "$pass" > "$passfile" )

    # openssl pkey håndterer både RSA og EC. Kollegaens 'openssl rsa
    # -traditional' feiler stille på EC-nøkler og faller tilbake til cp.
    local plainkey="$WORKDIR/p12-plain.key"
    ( umask 077; openssl pkey -in "$MACHINE_KEY" -out "$plainkey" 2>> "$LOG_FILE" ) \
        || { log_error "Klarte ikke lese privatnøkkelen"; return 1; }

    local tmp_p12="$WORKDIR/machine.p12"
    local -a pkcs12_args=(
        pkcs12 -export
        -in "$MACHINE_CERT"
        -inkey "$plainkey"
        -certfile "$CA_CERT"
        -name "$P12_FRIENDLY_NAME"
        -passout "file:$passfile"
        -out "$tmp_p12"
    )
    # Passord via fil, ikke 'pass:...' på kommandolinjen (synlig i ps).

    local built=false
    if [ "$P12_COMPAT" != "false" ]; then
        # Eldre klienter (bl.a. FortiClient) sliter med OpenSSL 3 sine
        # AES-256/PBKDF2-defaults i PKCS#12.
        if ( umask 077; openssl "${pkcs12_args[@]}" \
                -certpbe PBE-SHA1-3DES -keypbe PBE-SHA1-3DES -macalg SHA1 \
                2>> "$LOG_FILE" ); then
            built=true
            log "PKCS#12 bygget i kompatibilitetsmodus (3DES/SHA1)"
        elif [ "$P12_COMPAT" = "true" ]; then
            log_error "Kompatibilitetsmodus feilet (mangler legacy-algoritmer?)"
            return 1
        else
            log_warn "Kompatibilitetsmodus feilet — prøver moderne format"
        fi
    fi

    if [ "$built" = false ]; then
        ( umask 077; openssl "${pkcs12_args[@]}" 2>> "$LOG_FILE" ) \
            || { log_error "openssl pkcs12 -export feilet"; return 1; }
        log "PKCS#12 bygget i standardformat (AES-256/PBKDF2)"
    fi

    # Verifiser at fila lar seg åpne igjen MED NØYAKTIG det passordet brukeren
    # får oppgitt. Fanger både ødelagt pakking og at passordstrengen har blitt
    # forurenset på veien.
    if ! openssl pkcs12 -in "$tmp_p12" -noout -passin "pass:$pass" 2>> "$LOG_FILE"; then
        log_error "Kunne ikke åpne .p12 med det oppgitte passordet — avbryter"
        return 1
    fi
    log_success "Verifisert: .p12 lar seg åpne med det utleverte passordet"

    [ -e "$target_path" ] || record_state "FILE_CREATED:$target_path"

    local target_dir
    target_dir="$(dirname "$target_path")"
    if [ ! -d "$target_dir" ]; then
        install -d -m 0700 "$target_dir" || {
            log_error "Klarte ikke opprette $target_dir"
            return 1
        }
        [ -n "$target_user" ] && chown -R "$target_user" "$target_dir" 2>/dev/null || true
    fi

    # Legg ved en forklaring. Mappa skal overleve opprydding, og da må det
    # stå hvorfor — ellers forsvinner den ved første "rydde i hjemmemappa".
    local readme="${target_dir}/LES-MEG.txt"
    if [ ! -f "$readme" ]; then
        cat > "$readme" <<README
IKKE SLETT ELLER FLYTT FILENE I DENNE MAPPEN
============================================

${P12_FILENAME} inneholder sertifikatet FortiClient bruker for å koble
til VPN.

FortiClient lagrer STIEN til denne fila, ikke en kopi av innholdet. Den
leses ved hver tilkobling. Flyttes eller slettes fila, slutter VPN-en å
virke, og sertifikatet må importeres på nytt.

Fila oppdateres automatisk når maskinsertifikatet fornyes.

Opprettet av enterprise-network-deploy ${SCRIPT_VERSION}
README
        chmod 0644 "$readme"
        [ -n "$target_user" ] && chown "$target_user" "$readme" 2>/dev/null || true
        record_state "FILE_CREATED:$readme"
    fi

    ( umask 077; install -m 0600 "$tmp_p12" "$target_path" )

    # Fjern kopier som ligger igjen andre steder hos samme bruker — typisk
    # etter at plasseringen ble endret (hjemmekatalog -> skrivebord). Ellers
    # risikerer brukeren å importere en utdatert pakke.
    if [ -n "$target_user" ]; then
        local uhome old
        uhome="$(getent passwd "$target_user" | cut -d: -f6)"
        if [ -n "$uhome" ] && [ -d "$uhome" ]; then
            while IFS= read -r old; do
                [ "$old" = "$target_path" ] && continue
                log_warn "Fjerner utdatert kopi: $old"
                shred -u "$old" 2>/dev/null || rm -f "$old"
            done < <(find "$uhome" -maxdepth 3 -name "$P12_FILENAME" -type f 2>/dev/null)
        fi
    fi
    if [ -n "$target_user" ]; then
        chown "${target_user}:$(id -gn "$target_user" 2>/dev/null || printf '%s' "$target_user")" \
            "$target_path" 2>/dev/null || true
    fi

    # Passordet lagres root-only. Det havner ALDRI i loggfila.
    # Rollback-punktet MÅ registreres før fila opprettes.
    [ -e "$P12_PASSWORD_FILE" ] || record_state "FILE_CREATED:$P12_PASSWORD_FILE"
    ( umask 077; printf '%s\n' "$pass" > "$P12_PASSWORD_FILE" )
    chmod 0600 "$P12_PASSWORD_FILE"

    # Marker hvilket sertifikat pakka ble bygget fra, så neste kjøring kan
    # hoppe over jobben når ingenting er endret.
    ( umask 077; cert_fingerprint "$MACHINE_CERT" > "$P12_FP_MARKER" )
    rm -f "$P12_DELIVERED_MARKER"

    log_success ".p12 skrevet: $target_path"

    # Passordet skrives kun til terminalen, ikke til $LOG_FILE.
    if [ "$P12_PASSWORD_MODE" = "random" ]; then
        printf '\n'
        printf '  PKCS#12-passord: %s\n' "$pass"
        printf '  (lagret i %s, kun lesbar for root)\n\n' "$P12_PASSWORD_FILE"
    else
        printf '\n  PKCS#12-passord: se %s\n\n' "$P12_PASSWORD_FILE"
    fi

    unset pass
    return 0
}

# Fjerner utleverte .p12-filer eldre enn P12_RETENTION_DAYS.
cleanup_delivered_p12() {
    [ "$P12_RETENTION_DAYS" -gt 0 ] 2>/dev/null || return 0

    local removed=0 f
    for f in "${CERT_BASE_PATH}/${P12_FILENAME}" \
             /home/*/"${P12_FILENAME}" /home/*/*/"${P12_FILENAME}" \
             /home/*/*/*/"${P12_FILENAME}" \
             /root/"${P12_FILENAME}" /root/*/"${P12_FILENAME}"; do
        [ -f "$f" ] || continue
        if [ -n "$(find "$f" -maxdepth 0 -mtime "+${P12_RETENTION_DAYS}" 2>/dev/null)" ]; then
            shred -u "$f" 2>/dev/null || rm -f "$f"
            log "Ryddet bort utlevert .p12 etter ${P12_RETENTION_DAYS} dager: $f"
            removed=$((removed + 1))
        fi
    done

    if [ "$removed" -gt 0 ]; then
        ( umask 077; date -Is > "$P12_DELIVERED_MARKER" )
        log_success "Ryddet $removed .p12-fil(er)"
    fi
    return 0
}

install_p12_cleanup_timer() {
    [ "$P12_RETENTION_DAYS" -gt 0 ] 2>/dev/null || return 0
    command -v systemctl >/dev/null 2>&1 || return 0

    local unit=/etc/systemd/system/enterprise-p12-cleanup.service
    local timer=/etc/systemd/system/enterprise-p12-cleanup.timer

    install_self || return 1

    [ -e "$unit" ] || record_state "FILE_CREATED:$unit"
    cat > "$unit" <<UNIT
[Unit]
Description=Rydder bort utleverte 802.1X PKCS#12-filer

[Service]
Type=oneshot
ExecStart=${INSTALL_PATH} --cleanup-p12
UNIT
    chmod 0644 "$unit"

    [ -e "$timer" ] || record_state "FILE_CREATED:$timer"
    cat > "$timer" <<TIMER
[Unit]
Description=Daglig opprydding av utleverte PKCS#12-filer

[Timer]
OnCalendar=daily
Persistent=true
RandomizedDelaySec=1h

[Install]
WantedBy=timers.target
TIMER
    chmod 0644 "$timer"

    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl enable --now enterprise-p12-cleanup.timer >> "$LOG_FILE" 2>&1 || true
    log_success "Oppryddingstimer aktiv (${P12_RETENTION_DAYS} dager)"
    return 0
}

deploy_vpn_client_bundle() {
    log_section "[8C/9] VPN-klientpakke"

    if [ "$VPN_BUNDLE" = "false" ]; then
        log "VPN_BUNDLE=false — hopper over"
        return 0
    fi

    if [ "$TEST_MODE" = true ]; then
        log "[TEST] Ville installert ${#EXTRA_TRUST_ANCHORS[@]} ekstra trust anchor(s)"
        log "[TEST] Ville bygget PKCS#12 av maskin-sertifikatet"
        log "[TEST] Passordmodus: $P12_PASSWORD_MODE"

        # Vis hvem fila ville havnet hos. Utvelgelsen er den vanligste kilden
        # til overraskelser, så den skal kunne sjekkes uten å deploye.
        local t_pick t_user t_reason t_home t_dir
        t_pick="$(resolve_p12_user)" || true
        IFS='|' read -r t_user t_reason _ <<< "$t_pick"
        if [ -n "$t_user" ]; then
            t_home="$(getent passwd "$t_user" | cut -d: -f6)"
            t_dir="$(resolve_p12_dir "$t_user" "$t_home")"
            log "[TEST] .p12 ville havnet hos: $t_user ($t_reason)"
            log "[TEST]   sti: ${t_dir}/${P12_FILENAME}"
        elif [ "${P12_TARGET_USER:-}" = "" ]; then
            log "[TEST] .p12 ville havnet systemvidt: ${CERT_BASE_PATH}/${P12_FILENAME}"
        else
            log_warn "[TEST] Velger ingen bruker: ${t_reason:-ukjent}"
            case "$t_reason" in
                flere\ mulige*)
                    log_warn "[TEST] I en vanlig kjøring fra terminal blir du spurt."
                    log_warn "[TEST] Uten terminal (hook/ansible) legges .p12 systemvidt:" ;;
            esac
            log_warn "[TEST]   ${CERT_BASE_PATH}/${P12_FILENAME}"
        fi
        return 0
    fi

    # ── Kjedereparasjon via AIA ──────────────────────────────────────────────
    run_chain_fixes || log_warn "Kjedereparasjon ikke fullført for alle verter"

    # ── Ekstra trust anchors ─────────────────────────────────────────────────
    local anchor rc=0
    local anchors=( ${EXTRA_TRUST_ANCHORS[@]+"${EXTRA_TRUST_ANCHORS[@]}"} )
    if [ ${#anchors[@]} -gt 0 ]; then
        for anchor in "${anchors[@]}"; do
            [ -z "$anchor" ] && continue
            install_extra_anchor "$anchor" || rc=1
        done
        refresh_trust_store
        [ "$rc" -eq 0 ] && log_success "Mellom-CA på plass (modus: $EXTRA_ANCHOR_MODE)" \
                        || log_warn "Ett eller flere mellom-CA ble ikke installert"
    else
        log "Ingen ekstra trust anchors konfigurert (mellom-CA forvaltes utenfor skriptet)"
    fi

    # ── Kontroll av VPN-kjeden (leser bare) ──────────────────────────────────
    # Stopper ikke utrullingen: .p12 skal bygges uansett, og en brutt kjede
    # løses i trust store, ikke her.
    verify_vpn_chain || log_warn "VPN-kjeden er ikke i orden — se meldingene over"

    # ── PKCS#12 ──────────────────────────────────────────────────────────────
    local p12_user p12_path p12_pick p12_reason
    p12_pick="$(resolve_p12_user)" || true
    local p12_persist
    IFS='|' read -r p12_user p12_reason p12_persist <<< "$p12_pick"

    if [ -n "$p12_user" ]; then
        local p12_home p12_dir
        log "Valgte bruker: $p12_user ($p12_reason)"
        p12_home="$(getent passwd "$p12_user" | cut -d: -f6)"
        if [ -n "$p12_home" ] && [ -d "$p12_home" ]; then
            p12_dir="$(resolve_p12_dir "$p12_user" "$p12_home")"
            p12_path="${p12_dir}/${P12_FILENAME}"
            log "Målbruker: $p12_user ($p12_dir)"
        else
            log_warn "Hjemmekatalog mangler for $p12_user — legger .p12 i $CERT_BASE_PATH"
            p12_user=""
            p12_path="${CERT_BASE_PATH}/${P12_FILENAME}"
        fi
    else
        p12_user=""
        p12_path="${CERT_BASE_PATH}/${P12_FILENAME}"
        if [ "${P12_TARGET_USER:-}" = "" ]; then
            log ".p12 legges systemvidt: $p12_path"
        else
            log_warn "Legger ikke .p12 hos noen bruker: ${p12_reason:-ukjent}"
            log_warn ".p12 legges systemvidt i stedet: $p12_path"
            log_warn "Angi sluttbrukeren og kjør igjen:"
            log_warn "  sudo ${INSTALL_PATH} --vpn-bundle-only --user <brukernavn>"
            log_warn "(Er brukeren ikke opprettet ennå: kjør det etter første innlogging.)"
        fi
    fi

    LAST_P12_PATH="$p12_path"
    local p12_rc=0
    build_machine_p12 "$p12_user" "$p12_path" || p12_rc=$?
    if [ "$p12_rc" -eq 2 ]; then
        return 0   # enrollment pågår, ikke en feil
    elif [ "$p12_rc" -ne 0 ]; then
        log_error "Bygging av .p12 feilet"
        return 1
    fi

    if [ -n "$p12_user" ] && [ -f "$p12_path" ]; then
        # Husk valget, så fornyelseshooken og neste kjøring treffer samme bruker.
        if [ "${p12_persist:-0}" = "1" ]; then
            remember_p12_user "$p12_user"
        fi
        # Kopier skriptet la hos ANDRE brukere (f.eks. teknikeren) inneholder
        # maskinens privatnøkkel og skal ikke ligge igjen der.
        remove_p12_from_other_users "$p12_user"
    fi

    if [ "$P12_IMPORT_NSS" = true ] && [ -n "$p12_user" ] && [ -f "$p12_path" ]; then
        local nss_home nss_pass
        nss_home="$(getent passwd "$p12_user" | cut -d: -f6)"
        nss_pass="$(current_p12_password)" || nss_pass=""
        [ -n "$nss_pass" ] && import_p12_to_nssdb "$p12_user" "$nss_home" "$p12_path" "$nss_pass"
        unset nss_pass
    fi

    # Sørg for at pakka fornyes automatisk sammen med sertifikatet.
    cleanup_delivered_p12
    if [ "$RUN_MODE" != "vpn-only" ]; then
        install_renew_hook || log_warn "Fornyelseshook ble ikke installert"
        install_p12_cleanup_timer || log_warn "Oppryddingstimer ble ikke installert"
        local rid="enterprise-8021x-${HOSTNAME_SHORT}"
        if [ -f "$RENEW_HOOK_PATH" ] && ! renew_hook_is_attached "$rid"; then
            log_warn "Sporingen kaller ikke hooken ennå. Koble den på med:"
            log_warn "  getcert stop-tracking -i $rid && $INSTALL_PATH"
        fi
    fi

    if [ -n "$p12_user" ]; then
        log_warn "Merk: maskinens privatnøkkel ligger nå i $p12_user sin hjemmekatalog."
        log_warn "Den som eier den fila kan autentisere som denne maskinen."
    fi

    # ── VPN-klient: valgfri, ikke påkrevd ────────────────────────────────────
    local fc_found=false
    local p
    for p in /opt/forticlient /usr/bin/forticlient /opt/forticlient/fortitray; do
        [ -e "$p" ] && { fc_found=true; break; }
    done
    command -v forticlient >/dev/null 2>&1 && fc_found=true

    if [ "$fc_found" = true ]; then
        log_success "FortiClient funnet"
        if systemctl list-unit-files 2>/dev/null | grep -q '^forticlient'; then
            log "Importer .p12 i FortiClient, deretter: systemctl restart forticlient"
        else
            log "Importer .p12 i FortiClient og start klienten på nytt."
        fi
    else
        log "FortiClient ikke installert — .p12 og trust anchors ligger klare."
        log "Importer $p12_path når klienten er på plass."
    fi

    return 0
}

# ═════════════════════════════════════════════════════════════════════════════
# FORNYELSESHOOK, SELVINSTALLASJON, LOGROTATE
# ═════════════════════════════════════════════════════════════════════════════
#
# certmonger fornyer maskin-sertifikatet automatisk (typisk etter 2/3 av
# levetiden). Da byttes machine.crt/machine.key ut under føttene på alt som
# bruker dem. NetworkManager leser filene på nytt ved neste tilkobling, men
# en PKCS#12 som allerede er importert i FortiClient blir stående med den
# GAMLE nøkkelen og slutter å virke ved neste fornyelse.
#
# Derfor: installer skriptet på en fast sti og la certmonger kalle det med
# --vpn-bundle-only hver gang sertifikatet er lagret.

install_self() {
    local dest="$INSTALL_PATH"
    local src
    src="$(readlink -f "$0" 2>/dev/null || printf '%s' "$0")"

    if [ ! -r "$src" ]; then
        log_warn "Finner ikke egen kildefil — hopper over selvinstallasjon"
        return 1
    fi

    if [ -f "$dest" ] && cmp -s "$src" "$dest"; then
        log_debug "Allerede installert og identisk: $dest"
        return 0
    fi

    install -d -m 0755 "$(dirname "$dest")"
    [ -e "$dest" ] || record_state "FILE_CREATED:$dest"
    install -m 0700 -o root -g root "$src" "$dest" || {
        log_warn "Klarte ikke installere til $dest"
        return 1
    }
    log_success "Skript installert: $dest"
    return 0
}

install_renew_hook() {
    [ "$RENEW_HOOK" = true ] || { log_debug "RENEW_HOOK=false"; return 0; }

    install_self || return 1

    local hook="$RENEW_HOOK_PATH"
    install -d -m 0755 "$(dirname "$hook")"
    [ -e "$hook" ] || record_state "FILE_CREATED:$hook"

    cat > "$hook" <<HOOK
#!/bin/sh
# Kalles av certmonger etter at maskin-sertifikatet er fornyet og lagret.
# Generert av enterprise-network-deploy ${SCRIPT_VERSION} — ikke rediger manuelt.
set -u
exec ${INSTALL_PATH} --vpn-bundle-only --force-p12
HOOK
    chmod 0700 "$hook"
    set_selinux_context bin_t "$hook"
    log_success "Fornyelseshook installert: $hook"
    return 0
}

# Sjekk om en eksisterende sporing allerede har hooken.
renew_hook_is_attached() {
    getcert list -i "$1" 2>/dev/null | grep -q -- "$RENEW_HOOK_PATH"
}

install_logrotate() {
    local f=/etc/logrotate.d/enterprise-network-deploy
    [ -d /etc/logrotate.d ] || return 0
    [ -f "$f" ] && return 0
    cat > "$f" <<ROTATE
${LOG_FILE} ${ROLLBACK_LOG} {
    monthly
    rotate 6
    compress
    delaycompress
    missingok
    notifempty
    create 0600 root root
}
ROTATE
    chmod 0644 "$f"
    record_state "FILE_CREATED:$f"
    log_debug "logrotate-konfig installert: $f"
}

# ═════════════════════════════════════════════════════════════════════════════
# STATUSMODUS  (--status: leser bare, endrer ingenting)
# ═════════════════════════════════════════════════════════════════════════════

show_status() {
    local req_id
    req_id="enterprise-8021x-$(hostname -s 2>/dev/null || hostname)"

    printf '\n=== 802.1X-status på %s ===\n\n' "$(hostname)"
    if [ "$CONFIG_LOADED" = true ]; then
        printf 'Konfigfil: %s\n\n' "$CONFIG_FILE"
    else
        printf 'Konfigfil: ingen (innebygde verdier)\n\n'
    fi

    printf 'Sertifikat\n'
    if [ -s "$MACHINE_CERT" ]; then
        printf '  fil .............. %s\n' "$MACHINE_CERT"
        printf '  subject .......... %s\n' "$(cert_subject "$MACHINE_CERT")"
        printf '  utløper .......... %s\n' \
            "$(openssl x509 -in "$MACHINE_CERT" -noout -enddate 2>/dev/null | sed 's/notAfter=//')"
        printf '  sha256 ........... %s\n' "$(cert_fingerprint "$MACHINE_CERT")"
        if openssl x509 -in "$MACHINE_CERT" -noout -checkend 2592000 >/dev/null 2>&1; then
            printf '  gyldighet ........ OK (>30 dager)\n'
        elif openssl x509 -in "$MACHINE_CERT" -noout -checkend 0 >/dev/null 2>&1; then
            printf '  gyldighet ........ UTLØPER INNEN 30 DAGER\n'
        else
            printf '  gyldighet ........ UTLØPT\n'
        fi
    else
        printf '  fil .............. MANGLER (%s)\n' "$MACHINE_CERT"
    fi

    printf '\nCertmonger\n'
    if command -v getcert >/dev/null 2>&1; then
        printf '  status ........... %s\n' "$(cert_status "$req_id")"
        printf '  request-id ....... %s\n' "$req_id"
        if renew_hook_is_attached "$req_id"; then
            printf '  fornyelseshook ... aktiv\n'
        else
            printf '  fornyelseshook ... IKKE aktiv\n'
        fi
    else
        printf '  getcert .......... ikke installert\n'
    fi

    printf '\nCA-pinning\n'
    if [ -s "$PIN_FILE" ]; then
        while read -r fp subj; do
            [ -n "$fp" ] && printf '  %s  %s\n' "${fp:0:16}…" "$subj"
        done < "$PIN_FILE"
    else
        printf '  ingen pins lagret (%s)\n' "$PIN_FILE"
    fi

    printf '\nNetworkManager-profiler\n'
    local c dsm
    for c in "$WIRED_CONNECTION_NAME" "$WIFI_CONNECTION_NAME"; do
        if nm_conn_exists "$c"; then
            dsm="$(nm_get_field 802-1x.domain-suffix-match "$c")"
            printf '  %-16s finnes    server-match: %s\n' "$c" "${dsm:-<INGEN>}"
        else
            printf '  %-16s mangler\n' "$c"
        fi
    done

    printf '\nKryptopolicy\n'
    if command -v update-crypto-policies >/dev/null 2>&1; then
        local pol
        pol="$(update-crypto-policies --show 2>/dev/null || echo ukjent)"
        printf '  global ........... %s\n' "$pol"
        case "$pol" in
            *SHA1*) printf '  merk ............. SHA-1 er tillatt globalt — vurder scoped drop-in\n' ;;
        esac
    fi
    if [ -f "$SHA1_DROPIN" ]; then
        printf '  certmonger ....... SHA-1 drop-in aktiv\n'
    fi

    printf '\nVPN-klientpakke\n'
    if [ -s "$P12_TARGET_USER_FILE" ]; then
        printf '  sluttbruker ...... %s (lagret i %s)\n' \
            "$(head -1 "$P12_TARGET_USER_FILE")" "$P12_TARGET_USER_FILE"
    else
        printf '  sluttbruker ...... ikke lagret — velges ved neste kjøring\n'
    fi
    local found=false p
    for p in "${CERT_BASE_PATH}/${P12_FILENAME}" \
             /home/*/"${P12_FILENAME}" /home/*/*/"${P12_FILENAME}" \
             /home/*/*/*/"${P12_FILENAME}" \
             /root/"${P12_FILENAME}"; do
        [ -f "$p" ] || continue
        found=true
        printf '  %s  (%s)\n' "$p" "$(stat -c '%U %a' "$p" 2>/dev/null)"
    done
    if [ "$found" = false ]; then
        if [ -f "$P12_DELIVERED_MARKER" ]; then
            printf '  levert og ryddet bort %s\n' "$(cat "$P12_DELIVERED_MARKER" 2>/dev/null)"
        else
            printf '  ingen .p12 funnet\n'
        fi
    fi
    if [ "$P12_RETENTION_DAYS" -gt 0 ] 2>/dev/null; then
        printf '  oppbevaring ...... %s dager\n' "$P12_RETENTION_DAYS"
    else
        printf '  oppbevaring ...... ubegrenset\n'
    fi
    [ -f "$RENEW_HOOK_PATH" ] && printf '  hook ............. %s\n' "$RENEW_HOOK_PATH"

    printf '\nVPN-kjede\n'
    if [ -n "$VPN_CHAIN_EXPECT_ISSUER" ]; then
        local st
        st="$(p11_trust_state "$VPN_CHAIN_EXPECT_ISSUER" 2>/dev/null || true)"
        if trust_store_has_cn "$VPN_CHAIN_EXPECT_ISSUER"; then
            printf '  %s ... i trust store%s\n' "$VPN_CHAIN_EXPECT_ISSUER" "${st:+ (trust: $st)}"
        else
            printf '  %s ... MANGLER i trust store\n' "$VPN_CHAIN_EXPECT_ISSUER"
        fi
    fi
    local mp
    mp="$(list_misplaced_leaf_anchors)"
    if [ -n "$mp" ]; then
        printf '  serversertifikat i trusted CA (gjør ingen nytte):\n'
        printf '%s\n' "$mp" | cut -d'|' -f1 | sed 's/^/    /'
    fi
    local lo
    lo="$(list_script_anchor_leftovers)"
    if [ -n "$lo" ]; then
        printf '  rester fra eldre skriptversjon:\n'
        printf '%s\n' "$lo" | sed 's/^/    /'
    fi
    if [ "${#EXTRA_TRUST_ANCHORS[@]}" -gt 0 ]; then
        printf '  skriptet forvalter: %s anchor(s)\n' "${#EXTRA_TRUST_ANCHORS[@]}"
    else
        printf '  skriptet forvalter: ingenting (EXTRA_TRUST_ANCHORS=())\n'
    fi

    if [ -s "$GATEWAY_CERT_STORE" ]; then
        printf '  gateway-sertifikat: %s\n' "$(cert_subject "$GATEWAY_CERT_STORE")"
        printf '    utløper ........ %s\n' \
            "$(openssl x509 -in "$GATEWAY_CERT_STORE" -noout -enddate 2>/dev/null | sed 's/notAfter=//')"
        if openssl verify -CAfile "$SYSTEM_CA_BUNDLE" "$GATEWAY_CERT_STORE" >/dev/null 2>&1; then
            printf '    kjede .......... VALIDERER (VPN-tillit OK)\n'
        else
            printf '    kjede .......... VALIDERER IKKE — kjør --vpn-bundle-only\n'
        fi
    fi

    printf '\nFortiClient\n'
    if command -v rpm >/dev/null 2>&1 && rpm -q forticlient >/dev/null 2>&1; then
        printf '  versjon .......... %s\n' "$(fc_installed_version)"
        if command -v forticlient >/dev/null 2>&1; then
            local ems
            ems="$(forticlient epctrl detail 2>/dev/null | head -20 | tr '\n' ' ' | tr -s ' ')"
            printf '  EMS .............. %s\n' "${ems:-<ingen svar>}"
        fi
        if dnf versionlock list 2>/dev/null | grep -q forticlient; then
            printf '  versjonslås ...... aktiv\n'
        else
            printf '  versjonslås ...... IKKE aktiv (dnf update kan løfte versjonen)\n'
        fi
    else
        printf '  ikke installert\n'
    fi

    printf '\n'
    return 0
}

# ═════════════════════════════════════════════════════════════════════════════
# KJEDEREPARASJON VIA AIA
# ═════════════════════════════════════════════════════════════════════════════
#
# Mange gatewayer sender bare sitt eget sertifikat i handshaken, ikke
# mellom-CA-ene over. Windows skjuler problemet ved å hente de manglende
# leddene automatisk via AIA-feltet (Authority Information Access -> CA
# Issuers). OpenSSL gjør IKKE det, så på Linux feiler kjeden med
# "unable to get local issuer certificate" — nøyaktig det FortiClient viser.
#
# Her gjør vi det Windows gjør, én gang, og legger de manglende leddene
# lokalt så alle OpenSSL-baserte klienter på maskinen finner dem.
#
# Integritet: hvert hentede sertifikat MÅ validere mot trust store før det
# installeres. Derfor er http:// akseptabelt her — AIA-URLer er http per
# RFC 5280, og en angriper kan ikke bytte inn noe som validerer.

aia_ca_issuer_url() {
    openssl x509 -in "$1" -noout -text 2>/dev/null \
        | grep -i 'CA Issuers - URI:' \
        | sed 's/.*CA Issuers - URI://' | tr -d ' \r' | head -1
}

# Henter et sertifikat fra https://, http:// eller en lokal sti. Godtar DER,
# PEM og PKCS#7.
fetch_cert_any() {
    local url="$1" out="$2"
    local raw="${out}.raw"

    case "$url" in
        https://*)
            http_get "$url" "$raw" || return 1
            ;;
        http://*)
            curl -fsSL --connect-timeout 10 --max-time 60 --retry 2 \
                 -o "$raw" "$url" 2>> "$LOG_FILE" || return 1
            ;;
        *)
            [ -f "$url" ] || return 1
            cp "$url" "$raw" || return 1
            ;;
    esac

    [ -s "$raw" ] || return 1
    openssl x509   -in "$raw" -inform DER -out "$out" 2>/dev/null && return 0
    openssl x509   -in "$raw" -inform PEM -out "$out" 2>/dev/null && return 0
    openssl pkcs7  -in "$raw" -inform DER -print_certs -out "$out" 2>/dev/null \
        && [ -s "$out" ] && grep -q 'BEGIN CERTIFICATE' "$out" && return 0
    return 1
}

# Er sertifikatet faktisk synlig i CA-bundlen OpenSSL-klienter leser?
# Dette er forskjellen på "lagt i en katalog" og "virker". Nøytral tillit
# havner ikke nødvendigvis i den ekstraherte bundlen.
cert_reaches_system_bundle() {
    local pem="$1"
    local needle bundle

    # Første base64-linje er distinkt nok som søkestreng, og er mye raskere
    # enn å splitte og sammenligne 150+ sertifikater.
    needle="$(grep -v -- '-----' "$pem" | head -1)"
    [ -n "$needle" ] && [ "${#needle}" -ge 32 ] || return 1

    for bundle in "$SYSTEM_CA_BUNDLE" \
                  /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem \
                  /etc/ssl/certs/ca-certificates.crt; do
        [ -f "$bundle" ] || continue
        grep -qF "$needle" "$bundle" && return 0
    done
    return 1
}

# Finnes et CA-sertifikat med gitt CN i systemets trust store?
# Leser alle subjects i én passering (~80 ms for 150 sertifikater).
trust_store_has_cn() {
    local cn="$1"
    [ -n "$cn" ] && [ -s "$SYSTEM_CA_BUNDLE" ] || return 1

    # Rask vei: alle subjects i én passering. MEN crl2pkcs7 er alt-eller-
    # ingenting — ett sertifikat i bundlen som ikke lar seg lese, og hele
    # resultatet blir tomt. Det ga falsk "finner ikke" på Fedora 44 (4.15).
    local subjects
    subjects="$(openssl crl2pkcs7 -nocrl -certfile "$SYSTEM_CA_BUNDLE" 2>/dev/null \
                | openssl pkcs7 -print_certs -noout 2>/dev/null | grep -i '^subject=')"
    if [ -n "$subjects" ]; then
        grep -qiF "CN = ${cn}" <<< "$subjects" && return 0
        grep -qiF "CN=${cn}"   <<< "$subjects" && return 0
        # Bundlen ble lest, og CN-en finnes ikke.
        return 1
    fi

    # Sikker vei: ett sertifikat om gangen, med fast navneformat. Et
    # ulesbart sertifikat hoppes over i stedet for å velte hele søket.
    local dir f
    dir="$(mktemp -d -p "${WORKDIR:-/tmp}" cnscan.XXXXXX)" || return 1
    "$AWK" -v d="$dir" '
        /-----BEGIN CERTIFICATE-----/ { n++; f = sprintf("%s/c%04d.pem", d, n) }
        n > 0 { print > f }
        /-----END CERTIFICATE-----/   { if (f != "") close(f) }
    ' "$SYSTEM_CA_BUNDLE"
    for f in "$dir"/c*.pem; do
        if openssl x509 -in "$f" -noout -subject -nameopt RFC2253 2>/dev/null \
             | sed 's/^subject=//' | tr ',' '\n' | grep -qixF "CN=${cn}"; then
            rm -rf "$dir"
            return 0
        fi
    done
    rm -rf "$dir"
    return 1
}

# Hva sier p11-kit om et sertifikat med gitt label (= CN)?
# Skriver anchor | unspecified | distrusted, eller ingenting hvis ukjent.
# Samme kilde som "trust list" — Fedora/RHEL sin egen sannhet om trust store.
p11_trust_state() {
    local cn="$1"
    command -v trust >/dev/null 2>&1 || return 1
    trust list 2>/dev/null | "$AWK" -v cn="$cn" '
        /^pkcs11:/            { label = ""; next }
        /^[[:space:]]*label:/ { sub(/^[[:space:]]*label:[[:space:]]*/, ""); label = $0; next }
        /^[[:space:]]*trust:/ {
            sub(/^[[:space:]]*trust:[[:space:]]*/, "")
            if (tolower(label) == tolower(cn)) { print $0; exit }
        }'
}

# Samme oppslag, men på sertifikatets ID i stedet for navnet. p11-kit bruker
# Subject Key Identifier som pkcs11:id, så dette treffer uansett hva
# oppføringen heter. Skriver "trust|label", eller ingenting.
p11_trust_state_for_cert() {
    local pem="$1" ski id
    command -v trust >/dev/null 2>&1 || return 1
    ski="$(openssl x509 -in "$pem" -noout -ext subjectKeyIdentifier 2>/dev/null \
           | tail -1 | tr -d ' \t' | tr 'a-f' 'A-F')"
    [ -n "$ski" ] || return 1
    id="%${ski//:/%}"
    trust list 2>/dev/null | "$AWK" -v id="$id" '
        /^pkcs11:/ {
            hit = (toupper($0) ~ ("^PKCS11:ID=" id ";")) ? 1 : 0
            label = ""; next
        }
        hit && /^[[:space:]]*label:/ { sub(/^[[:space:]]*label:[[:space:]]*/, ""); label = $0; next }
        hit && /^[[:space:]]*trust:/ {
            sub(/^[[:space:]]*trust:[[:space:]]*/, "")
            print $0 "|" label; exit
        }'
}

# CN uten å avhenge av OpenSSL-versjonens utskriftsformat
# ("CN = x" i 3.0, "CN=x" i 3.5 / Fedora 44).
cert_cn() {
    openssl x509 -in "$1" -noout -subject -nameopt RFC2253 2>/dev/null \
        | sed 's/^subject=//' | tr ',' '\n' | sed -n 's/^CN=//p' | head -1
}

# Finner SERVERSERTIFIKATER (ikke CA) som ligger i anchors/. Et slikt
# sertifikat gjør ingen nytte der: OpenSSL krever en kjede opp til en rot, og
# et serversertifikat som "anker" gir ikke det. Typisk feil når man legger
# f.eks. *.indra.no i trusted CA i stedet for utstederen.
list_misplaced_leaf_anchors() {
    local d f txt subj iss
    for d in /etc/pki/ca-trust/source/anchors /usr/local/share/ca-certificates; do
        [ -d "$d" ] || continue
        for f in "$d"/*; do
            [ -f "$f" ] || continue
            txt="$(openssl x509 -in "$f" -noout -text 2>/dev/null \
                   || openssl x509 -in "$f" -inform DER -noout -text 2>/dev/null)" || continue
            [ -n "$txt" ] || continue
            grep -q 'CA:TRUE' <<< "$txt" && continue
            # Selvsignerte v1-røtter mangler ofte basicConstraints — ikke flagg dem.
            subj="$(grep -m1 'Subject:' <<< "$txt" | sed 's/.*Subject:[[:space:]]*//')"
            iss="$(grep -m1 'Issuer:' <<< "$txt" | sed 's/.*Issuer:[[:space:]]*//')"
            [ "$subj" = "$iss" ] && continue
            printf '%s|%s\n' "$f" "$subj"
        done
    done
    return 0
}

# Lister mellom-CA-filer som TIDLIGERE skriptversjoner la inn.
list_script_anchor_leftovers() {
    local d n ext
    for d in /etc/pki/ca-trust/source/anchors /etc/pki/ca-trust/source \
             /usr/local/share/ca-certificates; do
        [ -d "$d" ] || continue
        for n in "${SCRIPT_ANCHOR_LEFTOVERS[@]}"; do
            for ext in pem crt; do
                [ -f "$d/$n.$ext" ] && printf '%s\n' "$d/$n.$ext"
            done
        done
    done
    return 0
}

# Kontroll av VPN-kjeden. Leser bare — installerer og sletter ingenting.
# Returnerer 0 når kjeden er i orden eller ikke kan kontrolleres, 1 når
# den beviselig er brutt.
verify_vpn_chain() {
    [ "$VPN_CHAIN_CHECK" = true ] || return 0

    local leaf_src="${GATEWAY_CERT:-}"
    [ -z "$leaf_src" ] && [ -s "$GATEWAY_CERT_STORE" ] && leaf_src="$GATEWAY_CERT_STORE"

    local rc=0

    if [ -n "$leaf_src" ] && [ -f "$leaf_src" ]; then
        # Sterk kontroll: valider selve gateway-sertifikatet.
        local leaf="$WORKDIR/vpn-leaf.pem"
        if ! openssl x509 -in "$leaf_src" -out "$leaf" 2>/dev/null \
           && ! openssl x509 -in "$leaf_src" -inform DER -out "$leaf" 2>/dev/null; then
            log_warn "VPN-kjede: klarte ikke lese $leaf_src"
            return 0
        fi
        local issuer
        issuer="$(openssl x509 -in "$leaf" -noout -issuer 2>/dev/null | sed 's/^issuer=[[:space:]]*//')"
        if openssl verify -CAfile "$SYSTEM_CA_BUNDLE" "$leaf" >/dev/null 2>&1; then
            log_success "VPN-kjede: gateway-sertifikatet validerer mot systemets trust store"
            log "  $(cert_subject "$leaf")"
            log "  utsteder: $issuer"
        else
            log_error "VPN-kjede: gateway-sertifikatet validerer IKKE"
            log_error "  $(cert_subject "$leaf")"
            log_error "  utsteder: $issuer"
            log_error "  FortiClient vil feile med 'unable to get local issuer certificate'."
            local aia
            aia="$(aia_ca_issuer_url "$leaf" 2>/dev/null || true)"
            [ -n "$aia" ] && log_error "  Manglende mellom-CA kan hentes fra: $aia"
            log_error "  Legg det i /etc/pki/ca-trust/source/anchors/ og kjør update-ca-trust."
            rc=1
        fi
        check_gateway_cert_expiry "$leaf"
    elif [ -n "$VPN_CHAIN_EXPECT_ISSUER" ]; then
        # Svakere kontroll uten gateway-sertifikat: finnes utstederen?
        if trust_store_has_cn "$VPN_CHAIN_EXPECT_ISSUER"; then
            local st
            st="$(p11_trust_state "$VPN_CHAIN_EXPECT_ISSUER" 2>/dev/null || true)"
            log_success "VPN-kjede: '$VPN_CHAIN_EXPECT_ISSUER' finnes i systemets trust store${st:+ (trust: $st)}"
        else
            log_warn "VPN-kjede: finner ikke '$VPN_CHAIN_EXPECT_ISSUER' i systemets CA-bundle"
            log_warn "  ($SYSTEM_CA_BUNDLE)"
            log_warn "  FortiClient vil trolig feile med 'unable to get local issuer certificate'."
            local af found_src=""
            for af in /etc/pki/ca-trust/source/anchors/* /usr/local/share/ca-certificates/*; do
                [ -f "$af" ] || continue
                if [ "$(cert_cn "$af" 2>/dev/null)" = "$VPN_CHAIN_EXPECT_ISSUER" ]; then
                    found_src="$af"; break
                fi
            done
            if [ -n "$found_src" ]; then
                log_warn "  Fila ligger i $found_src, men er ikke med i bundlen."
                log_warn "  Kjør: sudo update-ca-trust extract"
            else
                log_warn "  Legg mellom-CA-et i /etc/pki/ca-trust/source/anchors/ og kjør update-ca-trust,"
                log_warn "  eller kontroller mot selve gateway-sertifikatet: --gateway-cert <fil>"
            fi
            rc=1
        fi
    fi

    # Serversertifikater lagt i anchors/ ved en feil.
    local misplaced mf msubj
    misplaced="$(list_misplaced_leaf_anchors)"
    if [ -n "$misplaced" ]; then
        log_warn "VPN-kjede: fant serversertifikat(er) i trusted CA — de gjør ingen nytte der:"
        while IFS='|' read -r mf msubj; do
            log_warn "  $mf"
            log_warn "    $msubj"
        done <<< "$misplaced"
        log_warn "  OpenSSL/FortiClient trenger UTSTEDEREN (mellom-CA-et), ikke serversertifikatet."
        log_warn "  Når VPN virker kan de fjernes:"
        while IFS='|' read -r mf msubj; do log_warn "    sudo rm '$mf'"; done <<< "$misplaced"
        log_warn "    sudo update-ca-trust extract"
    fi

    # Rester fra tidligere skriptversjoner er bare interessant når skriptet
    # IKKE forvalter mellom-CA-et selv.
    local left=""
    [ "${#EXTRA_TRUST_ANCHORS[@]}" -eq 0 ] && left="$(list_script_anchor_leftovers)"
    if [ -n "$left" ]; then
        log_warn "VPN-kjede: fant mellom-CA som en TIDLIGERE skriptversjon la inn:"
        while IFS= read -r f; do log_warn "  $f"; done <<< "$left"
        log_warn "  Skriptet forvalter ikke dette lenger. Er det lagt inn manuelt i"
        log_warn "  tillegg, kan kopien fjernes:"
        while IFS= read -r f; do log_warn "    sudo rm '$f'"; done <<< "$left"
        log_warn "    sudo update-ca-trust extract"
    fi

    return "$rc"
}

# Oppdater trust store etter at filer er lagt inn.
refresh_trust_store() {
    # Skriptet kjører med umask 077. Trust store skal være lesbar for alle.
    if [ -d /etc/pki/ca-trust/source/anchors ]; then
        ( umask 022; update-ca-trust extract ) >> "$LOG_FILE" 2>&1
    elif [ -d /usr/local/share/ca-certificates ]; then
        ( umask 022; update-ca-certificates ) >> "$LOG_FILE" 2>&1
    fi
    detect_system_ca_bundle || true
}

# Legger et CA-sertifikat inn i systemet etter EXTRA_ANCHOR_MODE.
#
# chain-only er den snevreste varianten: sertifikatet blir kjent for
# kjedebygging uten å være et tillitsanker. Men den virker bare hvis p11-kit
# faktisk tar det med i den ekstraherte bundlen OpenSSL-klienter leser — og
# det gjør den ikke i alle versjoner. Derfor måles resultatet.
#
# Setter PLACED_AS til "chain-only" eller "anchor".
PLACED_AS=""
place_ca_cert() {
    local pem="$1" name="$2"
    local anchor_dir="" neutral_dir="" ext="pem"

    if [ -d /etc/pki/ca-trust/source/anchors ]; then
        anchor_dir="/etc/pki/ca-trust/source/anchors"
        neutral_dir="/etc/pki/ca-trust/source"
    elif [ -d /usr/local/share/ca-certificates ]; then
        anchor_dir="/usr/local/share/ca-certificates"
        neutral_dir=""          # Debian har ingen nøytral variant
        ext="crt"
    else
        log_error "Fant ingen trust store-katalog"
        return 1
    fi

    local mode="$EXTRA_ANCHOR_MODE"
    if [ "$mode" != "anchor" ] && [ -z "$neutral_dir" ]; then
        log_warn "  Nøytral tillit finnes ikke på denne distroen — bruker anchor"
        mode="anchor"
    fi

    local dest
    if [ "$mode" = "anchor" ]; then
        dest="${anchor_dir}/${name}.${ext}"
        [ -e "$dest" ] || record_state "FILE_CREATED:$dest"
        install -m 0644 "$pem" "$dest"
        refresh_trust_store
        PLACED_AS="anchor"
        log "    plassering: systemets klarerte CA-lager ($dest)"
        if cert_reaches_system_bundle "$pem"; then
            log_success "    verifisert: sertifikatet er nå i systemets CA-bundle"
        else
            log_warn "    sertifikatet kom IKKE med i CA-bundlen — sjekk update-ca-trust"
        fi
        # Samme kontroll som "trust list", men på sertifikatets ID.
        local p11 p11_state p11_label cn
        cn="$(cert_cn "$pem")"
        if command -v trust >/dev/null 2>&1; then
            p11="$(p11_trust_state_for_cert "$pem" 2>/dev/null || true)"
            p11_state="${p11%%|*}"; p11_label="${p11#*|}"
            if [ "$p11_state" = "anchor" ]; then
                log_success "    trust list: '${p11_label:-$cn}' -> trust: anchor"
            elif [ -n "$p11_state" ]; then
                log_warn "    trust list: '${p11_label:-$cn}' -> trust: $p11_state (forventet anchor)"
            else
                local n_entries
                n_entries="$(trust list 2>/dev/null | grep -c '^pkcs11:' || true)"
                # Bundlen er det klientene leser — er sertifikatet der, er det
                # trust list-oppslaget som bommer, ikke installasjonen.
                if cert_reaches_system_bundle "$pem"; then
                    log "    trust list: fant ikke oppføringen (${n_entries:-0} oppføringer lest) —"
                    log "    sertifikatet ER i CA-bundlen (verifisert over), så dette er ikke en feil"
                else
                    log_warn "    trust list: finner ikke '$cn' (${n_entries:-0} oppføringer lest)"
                fi
            fi
        fi
        return 0
    fi

    # chain-only / auto: prøv nøytral tillit først.
    dest="${neutral_dir}/${name}.${ext}"
    [ -e "$dest" ] || record_state "FILE_CREATED:$dest"
    install -m 0644 "$pem" "$dest"
    rm -f "${anchor_dir}/${name}.${ext}"     # rydd etter tidligere anchor-kjøring
    refresh_trust_store

    if cert_reaches_system_bundle "$pem"; then
        PLACED_AS="chain-only"
        log_success "    plassering: kjedebygging uten tillitsanker ($dest)"
        log "    verifisert: sertifikatet er synlig i systemets CA-bundle"
        return 0
    fi

    if [ "$mode" = "chain-only" ]; then
        PLACED_AS="chain-only"
        log_warn "    Lagt i $dest, men sertifikatet havnet IKKE i bundlen"
        log_warn "    OpenSSL-klienter (inkl. FortiClient) vil ikke se det."
        log_warn "    p11-kit gir nøytrale sertifikater tomme trust-flagg."
        log_warn "    Sett EXTRA_ANCHOR_MODE=auto eller anchor for å få det til å virke."
        return 0
    fi

    # auto: nøytral plassering nådde ikke fram — eskaler.
    log "    nøytral plassering nådde ikke bundlen — eskalerer til tillitsanker"
    rm -f "$dest"
    dest="${anchor_dir}/${name}.${ext}"
    [ -e "$dest" ] || record_state "FILE_CREATED:$dest"
    install -m 0644 "$pem" "$dest"
    refresh_trust_store
    PLACED_AS="anchor"
    log "    plassering: systemets klarerte CA-lager ($dest)"
    return 0
}

# Installerer et mellom-CA lokalt etter at det er validert.
install_chain_cert() {
    local pem="$1"
    local subj fp name dest

    subj="$(cert_subject "$pem")"
    fp="$(cert_fingerprint "$pem")"
    name="$(printf '%s' "$subj" | sed 's/.*CN[ ]*=[ ]*//; s/,.*//' \
            | tr -c 'A-Za-z0-9._-' '_' | cut -c1-60)"
    [ -n "$name" ] || name="chain-${fp:0:12}"

    log_success "  Installert: $subj"
    log "    sha256: $fp"
    place_ca_cert "$pem" "$name" || return 1
    return 0
}

# Hovedrutine. Tar "vert" eller "vert:port".
# Følger AIA fra et leaf-sertifikat og installerer manglende mellom-CA.
# Tar leaf-fila som argument, så den virker både fra en TLS-forbindelse og
# fra et sertifikat noen har sendt oss på e-post.
#
# $1 = leaf-PEM, $2 = etikett til logg, $3 = evt. mellomsertifikater vi
#      allerede har (kan være tom fil)
complete_chain_from_leaf() {
    local leaf="$1" label="$2" extra="$3"
    local dir
    dir="$(dirname "$leaf")"

    log "  Sertifikat: $(cert_subject "$leaf")"
    log "  Utsteder:   $(openssl x509 -in "$leaf" -noout -issuer | sed 's/^issuer=[[:space:]]*//')"
    log "  Utløper:    $(openssl x509 -in "$leaf" -noout -enddate | sed 's/notAfter=//')"

    if openssl verify -CAfile "$SYSTEM_CA_BUNDLE" -untrusted "$extra" "$leaf" >/dev/null 2>&1; then
        log_success "Kjeden validerer allerede — ingenting å reparere"
        return 0
    fi

    log_warn "Kjeden validerer ikke. Følger AIA for å finne manglende ledd."

    local current="$leaf" i url next
    for i in 1 2 3 4 5; do
        url="$(aia_ca_issuer_url "$current")"
        if [ -z "$url" ]; then
            log_warn "  Ingen CA Issuers-URL i $(cert_subject "$current")"
            break
        fi
        log "  [$i] Henter utsteder: $url"

        next="$dir/aia-${i}.pem"
        if ! fetch_cert_any "$url" "$next"; then
            log_error "  Nedlasting feilet: $url"
            break
        fi
        log "      -> $(cert_subject "$next")"
        cat "$next" >> "$extra"
        current="$next"

        if openssl verify -CAfile "$SYSTEM_CA_BUNDLE" -untrusted "$extra" "$leaf" >/dev/null 2>&1; then
            log_success "  Kjeden er komplett etter $i ledd"
            break
        fi
    done

    if ! openssl verify -CAfile "$SYSTEM_CA_BUNDLE" -untrusted "$extra" "$leaf" >/dev/null 2>&1; then
        log_error "Klarte ikke fullføre kjeden for $label"
        openssl verify -CAfile "$SYSTEM_CA_BUNDLE" -untrusted "$extra" "$leaf" 2>&1 | log_output
        log_error "  Rot-CA-en kan mangle i trust store, eller AIA peker feil."
        return 1
    fi

    log "Installerer manglende mellom-sertifikat(er):"
    local f installed=0
    while IFS= read -r f; do
        openssl x509 -in "$f" -noout -text 2>/dev/null | grep -qE 'CA:TRUE' || continue
        if openssl verify -CAfile "$SYSTEM_CA_BUNDLE" "$f" >/dev/null 2>&1 \
           || openssl verify -CAfile "$SYSTEM_CA_BUNDLE" -partial_chain "$f" >/dev/null 2>&1; then
            install_chain_cert "$f" && installed=$((installed + 1))
        else
            log_warn "  Hopper over (validerer ikke): $(cert_subject "$f")"
        fi
    done < <(split_pem_bundle "$extra" "$dir/split" "chain-")

    if [ "$installed" -eq 0 ]; then
        log_warn "Ingen sertifikater installert"
        return 1
    fi
    refresh_trust_store

    # Det definitive beviset: validerer leaf-sertifikatet nå UTEN hjelp?
    if openssl verify -CAfile "$SYSTEM_CA_BUNDLE" "$leaf" >/dev/null 2>&1; then
        log_success "Bekreftet: $label validerer nå mot systemets trust store alene"
        return 0
    fi
    log_warn "Installert, men leaf validerer fortsatt ikke uten hjelp"
    return 1
}

# Varsler hvis gateway-sertifikatet nærmer seg utløp. Går det ut, feiler VPN
# for alle samtidig, og det nye sertifikatet kan ha en annen utsteder.
check_gateway_cert_expiry() {
    local cert="$1"
    [ -s "$cert" ] || return 0
    local secs=$(( GATEWAY_CERT_WARN_DAYS * 86400 ))
    if openssl x509 -in "$cert" -noout -checkend "$secs" >/dev/null 2>&1; then
        return 0
    fi
    local enddate
    enddate="$(openssl x509 -in "$cert" -noout -enddate | sed 's/notAfter=//')"
    if openssl x509 -in "$cert" -noout -checkend 0 >/dev/null 2>&1; then
        log_warn "Gateway-sertifikatet utløper innen ${GATEWAY_CERT_WARN_DAYS} dager: $enddate"
        log_warn "  Når det fornyes kan utstederen endre seg — kjør skriptet på nytt"
        log_warn "  etterpå, så hentes riktig mellom-CA automatisk."
    else
        log_error "Gateway-sertifikatet er UTLØPT: $enddate"
        log_error "  VPN vil feile til det er fornyet på gatewayen."
    fi
    return 0
}

# Kjedereparasjon med utgangspunkt i en lokal sertifikatfil.
fix_chain_from_file() {
    local src="$1"
    log "Undersøker sertifikatkjede fra fil: $src"

    if [ ! -f "$src" ]; then
        log_error "Finner ikke sertifikatfila: $src"
        return 1
    fi

    local dir="$WORKDIR/chain-file"
    mkdir -p "$dir"
    local leaf="$dir/leaf.pem" extra="$dir/extra.pem"
    : > "$extra"

    # Godta PEM, DER og PKCS#7.
    if ! openssl x509 -in "$src" -out "$leaf" 2>/dev/null \
       && ! openssl x509 -in "$src" -inform DER -out "$leaf" 2>/dev/null; then
        if openssl pkcs7 -in "$src" -inform DER -print_certs -out "$dir/p7.pem" 2>/dev/null \
           || openssl pkcs7 -in "$src" -print_certs -out "$dir/p7.pem" 2>/dev/null; then
            # Første cert = leaf, resten = mellomledd vi allerede har.
            "$AWK" '/-----BEGIN CERTIFICATE-----/{n++} n==1{print} /-----END CERTIFICATE-----/{if(n==1) exit}' \
                "$dir/p7.pem" > "$leaf"
            "$AWK" '/-----BEGIN CERTIFICATE-----/{n++} n>1{print}' "$dir/p7.pem" >> "$extra"
        else
            log_error "Fila er ikke et gyldig sertifikat (PEM/DER/PKCS#7): $src"
            return 1
        fi
    fi

    check_gateway_cert_expiry "$leaf"

    # Ta vare på sertifikatet så senere kjøringer og --status kan bruke det.
    if [ "$TEST_MODE" = false ]; then
        install -d -m 0700 "$(dirname "$GATEWAY_CERT_STORE")" 2>/dev/null || true
        [ -e "$GATEWAY_CERT_STORE" ] || record_state "FILE_CREATED:$GATEWAY_CERT_STORE"
        install -m 0644 "$leaf" "$GATEWAY_CERT_STORE"
    fi

    complete_chain_from_leaf "$leaf" "$(cert_subject "$leaf")" "$extra"
}

fix_incomplete_chain() {
    local hostport="$1"
    local host port
    case "$hostport" in
        *:*) host="${hostport%:*}"; port="${hostport##*:}" ;;
        *)   host="$hostport";      port=443 ;;
    esac

    log "Undersøker sertifikatkjede: ${host}:${port}"

    local dir="$WORKDIR/chain-${host//[^A-Za-z0-9]/_}"
    mkdir -p "$dir"
    local served="$dir/served.pem" leaf="$dir/leaf.pem" extra="$dir/extra.pem"
    : > "$extra"

    # MERK: s_client returnerer non-zero når kjeden ikke validerer — altså
    # alltid i nettopp det scenariet vi er her for å fikse. Exit-koden kan
    # derfor ikke brukes; vi sjekker om vi faktisk fikk et sertifikat.
    timeout 20 openssl s_client -connect "${host}:${port}" -servername "$host" \
            -showcerts </dev/null > "$served" 2>> "$LOG_FILE" || true

    if [ ! -s "$served" ] || ! grep -q 'BEGIN CERTIFICATE' "$served"; then
        log_error "Fikk ikke sertifikat fra ${host}:${port}"
        log_error "  Er sertifikatet kun eksponert via IKEv2, prøv gatewayens"
        log_error "  web-/SSL-VPN-port i stedet (ofte 443 eller 10443)."
        return 1
    fi

    # Første sertifikat i utskriften er serverens eget.
    "$AWK" '/-----BEGIN CERTIFICATE-----/{n++} n==1{print} /-----END CERTIFICATE-----/{if(n==1) exit}' \
        "$served" > "$leaf"
    if ! openssl x509 -in "$leaf" -noout >/dev/null 2>&1; then
        log_error "Klarte ikke lese serverens sertifikat"
        return 1
    fi

    # Mellomsertifikater serveren faktisk sendte.
    local served_count
    served_count="$(grep -c 'BEGIN CERTIFICATE' "$served" || true)"
    log "  Serveren sendte $served_count sertifikat(er)"
    if [ "$served_count" -gt 1 ]; then
        "$AWK" '/-----BEGIN CERTIFICATE-----/{n++} n>1{print}' "$served" >> "$extra"
    fi

    check_gateway_cert_expiry "$leaf"
    complete_chain_from_leaf "$leaf" "${host}:${port}" "$extra"
}

run_chain_fixes() {
    local hosts=( ${FIX_CHAIN_HOSTS[@]+"${FIX_CHAIN_HOSTS[@]}"} )
    local certfile="$GATEWAY_CERT"

    # Har vi lagret gatewayens sertifikat tidligere, bruk det som
    # verifikasjonsmål selv om ingen fil ble oppgitt denne gangen.
    [ -z "$certfile" ] && [ -s "$GATEWAY_CERT_STORE" ] && certfile="$GATEWAY_CERT_STORE"

    [ ${#hosts[@]} -gt 0 ] || [ -n "$certfile" ] || return 0

    log_section "Kjedereparasjon (AIA)"
    if [ "$TEST_MODE" = true ]; then
        local h
        for h in ${hosts[@]+"${hosts[@]}"}; do
            log "[TEST] Ville undersøkt og reparert kjeden for: $h"
        done
        [ -n "$certfile" ] && log "[TEST] Ville fulgt AIA fra sertifikatfil: $certfile"
        return 0
    fi

    local rc=0 h
    if [ -n "$certfile" ]; then
        fix_chain_from_file "$certfile" || rc=1
    fi
    for h in ${hosts[@]+"${hosts[@]}"}; do
        [ -z "$h" ] && continue
        fix_incomplete_chain "$h" || rc=1
    done
    return "$rc"
}

# ═════════════════════════════════════════════════════════════════════════════
# FORTICLIENT-UTRULLING
# ═════════════════════════════════════════════════════════════════════════════
#
# Installerer en forhåndskonfigurert FortiClient-RPM og registrerer endepunktet
# mot EMS, slik at brukeren slipper å taste inn invitasjonskoden manuelt.
#
# Kjøres bare når FORTICLIENT_RPM er satt.

fc_installed_version() {
    rpm -q --qf '%{VERSION}-%{RELEASE}' forticlient 2>/dev/null || true
}

fc_package_version() {
    rpm -qp --qf '%{VERSION}-%{RELEASE}' "$1" 2>/dev/null || true
}

# Returnerer 0 hvis $1 er en nyere versjon enn $2.
# sort -V holder for versjonsstrenger av typen 7.4.8-1234 og krever ingen
# ekstra pakker (python3-rpm/rpmdevtools er ikke garantert installert).
fc_version_newer() {
    [ "$1" = "$2" ] && return 1
    [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -1)" = "$1" ]
}

verify_rpm_integrity() {
    local rpmfile="$1"

    if [ -n "$FORTICLIENT_RPM_SHA256" ]; then
        local actual
        actual="$(sha256sum "$rpmfile" | "$AWK" '{print $1}')"
        local expected
        expected="$(printf '%s' "$FORTICLIENT_RPM_SHA256" | tr -d ': \n' | tr 'A-F' 'a-f')"
        if [ "$actual" != "$expected" ]; then
            log_error "SHA-256 på RPM stemmer ikke"
            log_error "  forventet: $expected"
            log_error "  fikk:      $actual"
            return 1
        fi
        log_success "SHA-256 verifisert"
    else
        log_warn "FORTICLIENT_RPM_SHA256 ikke satt — integriteten kontrolleres ikke"
        log_warn "  sha256sum $(basename "$rpmfile") -> legg verdien i konfigfila"
    fi

    # GPG-signatur. Fortinet signerer sine pakker; en EMS-generert pakke er
    # ompakket og kan mangle signatur.
    local sigout
    sigout="$(rpm -K "$rpmfile" 2>&1)"
    printf '%s\n' "$sigout" >> "$LOG_FILE"
    if grep -qi 'signatures OK\|pgp.*OK' <<< "$sigout"; then
        log_success "GPG-signatur OK"
    elif grep -qi 'NOKEY\|NOT OK\|MISSING KEYS' <<< "$sigout"; then
        if [ "$FORTICLIENT_REQUIRE_SIGNATURE" = true ]; then
            log_error "RPM mangler gyldig GPG-signatur: $sigout"
            log_error "Importer Fortinets nøkkel, eller sett"
            log_error "FORTICLIENT_REQUIRE_SIGNATURE=false hvis pakka er EMS-generert."
            return 1
        fi
        log_warn "RPM er usignert eller nøkkelen mangler ($sigout)"
        log_warn "  Stol da på SHA-256-pinningen og på hvor pakka kommer fra."
    fi
    return 0
}

lock_forticlient_version() {
    [ "$FORTICLIENT_VERSIONLOCK" = true ] || return 0

    if dnf versionlock --help >/dev/null 2>&1; then
        dnf versionlock delete forticlient >/dev/null 2>&1 || true
        if dnf versionlock add forticlient >> "$LOG_FILE" 2>&1; then
            log_success "Versjonslås satt — dnf update vil ikke løfte forticlient"
            return 0
        fi
    fi

    log_warn "versionlock-plugin mangler. Installer den med:"
    log_warn "  dnf install -y python3-dnf-plugin-versionlock  (eller dnf5-plugin-versionlock)"
    log_warn "Uten den kan en dnf update løfte forticlient til en nyere versjon."
    return 0
}

register_with_ems() {
    { [ -n "$EMS_INVITATION_CODE" ] || [ -n "$EMS_SERVER" ]; } || {
        log "Ingen EMS-registrering konfigurert"
        return 0
    }

    command -v forticlient >/dev/null 2>&1 || {
        log_warn "forticlient-CLI ikke tilgjengelig ennå — hopper over EMS-registrering"
        return 0
    }

    # Allerede registrert?
    if forticlient epctrl detail 2>/dev/null | grep -qiE 'connected|registered'; then
        log "Endepunktet er allerede registrert mot EMS"
        return 0
    fi

    local -a args=(epctrl register)
    if [ -n "$EMS_INVITATION_CODE" ]; then
        args+=("$EMS_INVITATION_CODE")
        log "Registrerer mot EMS med invitasjonskode"
    else
        args+=("$EMS_SERVER")
        [ -n "$EMS_SITE" ] && args+=(-s "$EMS_SITE")
        log "Registrerer mot EMS: $EMS_SERVER${EMS_SITE:+ (site: $EMS_SITE)}"
    fi

    # Koden logges bevisst ikke — den er et registreringshemmelig.
    local out
    if out="$(forticlient "${args[@]}" 2>&1)"; then
        if grep -qi 'saml url' <<< "$out"; then
            log_warn "EMS krever SAML-innlogging. Registreringen må fullføres i nettleser:"
            printf '%s\n' "$out" | grep -i 'https://' || true
        else
            log_success "Registrert mot EMS"
        fi
    else
        log_warn "EMS-registrering feilet — kan fullføres manuelt senere"
        printf '%s\n' "$out" >> "$LOG_FILE"
    fi
    return 0
}

deploy_forticlient() {
    log_section "[8D/9] FortiClient"

    if [ -z "$FORTICLIENT_RPM" ]; then
        log "FORTICLIENT_RPM ikke satt — hopper over"
        return 0
    fi

    case "$OS" in
        fedora|rhel|centos|rocky|almalinux) : ;;
        *)
            log_warn "FortiClient-RPM støttes kun på RPM-baserte systemer (OS=$OS)"
            return 0
            ;;
    esac

    if [ "$TEST_MODE" = true ]; then
        log "[TEST] Ville installert: $FORTICLIENT_RPM"
        log "[TEST] Forventet versjon: ${FORTICLIENT_EXPECTED_VERSION:-<uspesifisert>}"
        log "[TEST] Nedgradering tillatt: $FORTICLIENT_ALLOW_DOWNGRADE"
        log "[TEST] Versjonslås: $FORTICLIENT_VERSIONLOCK"
        [ -n "$EMS_INVITATION_CODE" ] && log "[TEST] Ville registrert mot EMS med invitasjonskode"
        [ -n "$EMS_SERVER" ] && log "[TEST] Ville registrert mot EMS: $EMS_SERVER"
        return 0
    fi

    # ── Skaff pakka ──────────────────────────────────────────────────────────
    local rpmfile
    case "$FORTICLIENT_RPM" in
        https://*)
            rpmfile="$WORKDIR/forticlient.rpm"
            log "Laster ned RPM: $FORTICLIENT_RPM"
            http_get "$FORTICLIENT_RPM" "$rpmfile" || {
                log_error "Nedlasting feilet"
                return 1
            }
            ;;
        http://*)
            log_error "Nekter å hente RPM over ukryptert HTTP: $FORTICLIENT_RPM"
            return 1
            ;;
        *)
            rpmfile="$FORTICLIENT_RPM"
            [ -f "$rpmfile" ] || { log_error "Finner ikke RPM: $rpmfile"; return 1; }
            ;;
    esac

    verify_rpm_integrity "$rpmfile" || return 1

    local pkg_ver cur_ver
    pkg_ver="$(fc_package_version "$rpmfile")"
    cur_ver="$(fc_installed_version)"
    [ -n "$pkg_ver" ] || { log_error "Klarte ikke lese versjon fra RPM"; return 1; }

    log "Pakke:      forticlient-$pkg_ver"
    log "Installert: ${cur_ver:-<ingen>}"

    if [ -n "$FORTICLIENT_EXPECTED_VERSION" ]; then
        case "$pkg_ver" in
            "$FORTICLIENT_EXPECTED_VERSION"*) : ;;
            *)
                log_error "RPM er versjon $pkg_ver, men FORTICLIENT_EXPECTED_VERSION=$FORTICLIENT_EXPECTED_VERSION"
                log_error "Feil pakke — avbryter for sikkerhets skyld."
                return 1
                ;;
        esac
    fi

    # ── Installer / erstatt ──────────────────────────────────────────────────
    if [ "$cur_ver" = "$pkg_ver" ]; then
        log "Riktig versjon allerede installert"
    else
        local is_downgrade=false
        if [ -n "$cur_ver" ] && fc_version_newer "$cur_ver" "$pkg_ver" 2>/dev/null; then
            is_downgrade=true
        fi

        if [ "$is_downgrade" = true ]; then
            if [ "$FORTICLIENT_ALLOW_DOWNGRADE" != true ]; then
                log_error "Installert versjon ($cur_ver) er nyere enn pakka ($pkg_ver)."
                log_error "Sett FORTICLIENT_ALLOW_DOWNGRADE=true for å nedgradere bevisst."
                return 1
            fi
            log_warn "NEDGRADERER FortiClient: $cur_ver -> $pkg_ver"
            log_warn "En nyere versjon kan inneholde sikkerhetsfikser som går tapt."
        fi

        record_state "SERVICE_STATE:forticlient"

        local ok=false
        if [ "$is_downgrade" = true ]; then
            if dnf downgrade -y "$rpmfile" >> "$LOG_FILE" 2>&1; then
                ok=true
            elif rpm -Uvh --oldpackage "$rpmfile" >> "$LOG_FILE" 2>&1; then
                ok=true
            fi
        else
            if dnf install -y "$rpmfile" >> "$LOG_FILE" 2>&1; then
                ok=true
            fi
        fi

        # Siste utvei: fjern og installer på nytt. Gjøres bare når vi allerede
        # vet at pakka finnes og er verifisert.
        if [ "$ok" = false ] && [ -n "$cur_ver" ] && [ "$FORTICLIENT_ALLOW_DOWNGRADE" = true ]; then
            log_warn "Direkte bytte feilet — fjerner og installerer på nytt"
            dnf remove -y forticlient >> "$LOG_FILE" 2>&1 || true
            dnf install -y "$rpmfile" >> "$LOG_FILE" 2>&1 && ok=true
        fi

        if [ "$ok" = false ]; then
            log_error "Installasjon av FortiClient feilet — se $LOG_FILE"
            return 1
        fi

        local new_ver
        new_ver="$(fc_installed_version)"
        if [ "$new_ver" != "$pkg_ver" ]; then
            log_error "Etter installasjon er versjonen $new_ver, forventet $pkg_ver"
            return 1
        fi
        log_success "FortiClient $new_ver installert"
    fi

    lock_forticlient_version

    # ── Start tjenesten ──────────────────────────────────────────────────────
    local unit
    for unit in forticlient forticlient-scheduler fortivpn; do
        if systemctl list-unit-files 2>/dev/null | grep -q "^${unit}\.service"; then
            systemctl enable --now "$unit" >> "$LOG_FILE" 2>&1 || true
            log_debug "Tjeneste startet: $unit"
        fi
    done
    sleep 3

    register_with_ems
    return 0
}

# ═════════════════════════════════════════════════════════════════════════════
# PRE-FLIGHT
# ═════════════════════════════════════════════════════════════════════════════

preflight_checks() {
    log_section "Pre-flight"
    local ok=true

    if [ "$(id -u)" -eq 0 ]; then
        log_success "Kjører som root"
    else
        log_error "Må kjøres som root"
        [ "$TEST_MODE" = false ] && ok=false
    fi

    require_cmd openssl curl systemctl grep sed || ok=false
    detect_awk || ok=false
    log_success "AWK: ${AWK:-<ingen>}"

    case "$SCEP_URL" in
        https://*) : ;;
        *)
            log_error "SCEP_URL må bruke https:// — fikk: $SCEP_URL"
            ok=false
            ;;
    esac

    local ndes_host
    ndes_host="${SCEP_URL#https://}"
    ndes_host="${ndes_host%%/*}"
    ndes_host="${ndes_host%%:*}"

    if [ "$TEST_MODE" = true ]; then
        log "[TEST] Ville testet DNS og HTTPS mot: $ndes_host"
    else
        if timeout 8 getent hosts "$ndes_host" >/dev/null 2>&1; then
            log_success "DNS OK: $ndes_host"
        else
            log_warn "DNS-oppslag feilet for $ndes_host"
        fi

        detect_system_ca_bundle || ok=false

        if http_head "$SCEP_URL"; then
            log_success "SCEP-endepunkt nåbart med verifisert TLS"
        else
            if [ "$ALLOW_INSECURE_TLS" = true ]; then
                log_warn "SCEP nådd med TLS-verifisering AV (ALLOW_INSECURE_TLS=true)"
            else
                log_error "Når ikke SCEP-URL med verifisert TLS: $SCEP_URL"
                log_error "Sjekk nett/proxy, eller at NDES sitt TLS-sertifikat er klarert."
                ok=false
            fi
        fi
    fi

    local avail
    avail="$(df -Pk /etc 2>/dev/null | "$AWK" 'NR==2 {print $4+0}')"
    avail="${avail:-0}"
    if [ "$avail" -gt 10240 ]; then
        log_success "Ledig diskplass: ${avail} KB"
    else
        log_error "For lite diskplass: ${avail} KB (trenger >10 MB)"
        ok=false
    fi

    if [ "$ALLOW_INSECURE_TLS" = true ]; then
        log_warn "ALLOW_INSECURE_TLS=true — TLS-verifisering mot NDES er AV."
        log_warn "CA-kjeden som brukes til 802.1X-servervalidering hentes da uverifisert."
    fi
    if [ -z "$RADIUS_DOMAIN_SUFFIX" ]; then
        log_warn "RADIUS_DOMAIN_SUFFIX er tom — klienten godtar ETHVERT servercert"
        log_warn "utstedt av CA-en. Sett den til RADIUS-serverens domenesuffiks."
    fi

    if [ "$ok" = false ] && [ "$TEST_MODE" = false ]; then
        log_error "Pre-flight FEILET"
        exit 1
    fi
    log_success "Pre-flight OK"
}

# ═════════════════════════════════════════════════════════════════════════════
# NM-HJELPERE
# ═════════════════════════════════════════════════════════════════════════════

nm_unescape() { sed 's/\\:/:/g; s/\\\\/\\/g'; }

nm_get_field() {
    # nm_get_field <felt> <profilnavn>
    nmcli -t -f "$1" connection show "$2" 2>/dev/null | sed 's/^[^:]*://' || true
}

nm_conn_exists() { nmcli -t -f NAME connection show 2>/dev/null | nm_unescape | grep -Fxq "$1"; }

# ═════════════════════════════════════════════════════════════════════════════
# VERIFISERING
# ═════════════════════════════════════════════════════════════════════════════

cert_status() {
    getcert list -i "$1" 2>/dev/null | grep -m1 'status:' | "$AWK" '{print $2}' || true
}

verify_deployment() {
    log_section "[9/9] Verifisering"
    local ok=true

    if [ "$TEST_MODE" = true ]; then
        log "[TEST] Ville verifisert sertifikat, certmonger-sporing og NM-profiler"
        return 0
    fi

    local req_id="enterprise-8021x-${HOSTNAME_SHORT}"
    local status
    status="$(cert_status "$req_id")"

    if [ -s "$MACHINE_CERT" ] && [ -f "$MACHINE_KEY" ]; then
        if openssl x509 -in "$MACHINE_CERT" -noout -checkend 86400 >/dev/null 2>&1; then
            log_success "Sertifikat gyldig (utløper ikke innen 24t)"
            log "  Subject: $(cert_subject "$MACHINE_CERT")"
            log "  Utløper: $(openssl x509 -in "$MACHINE_CERT" -noout -enddate | sed 's/notAfter=//')"
            log "  SHA256:  $(cert_fingerprint "$MACHINE_CERT")"
        else
            log_error "Sertifikat ugyldig eller utløper snart"
            ok=false
        fi

        # Sjekk at nøkkel og sertifikat faktisk hører sammen.
        local c_mod k_mod
        c_mod="$(openssl x509 -in "$MACHINE_CERT" -noout -modulus 2>/dev/null | openssl sha256)"
        k_mod="$(openssl rsa  -in "$MACHINE_KEY"  -noout -modulus 2>/dev/null | openssl sha256)"
        if [ -n "$c_mod" ] && [ "$c_mod" = "$k_mod" ]; then
            log_success "Privatnøkkel matcher sertifikatet"
        elif [ -n "$k_mod" ]; then
            log_error "Privatnøkkel matcher IKKE sertifikatet"
            ok=false
        fi

        # Kjeden må validere mot CA-fila NM bruker, ellers feiler EAP-TLS.
        if openssl verify -CAfile "$CA_CERT" "$MACHINE_CERT" >/dev/null 2>&1; then
            log_success "Sertifikatkjede validerer mot $CA_CERT"
        else
            log_warn "Sertifikatet validerer ikke mot $CA_CERT — sjekk kjeden"
        fi

        local perm
        perm="$(stat -c '%a' "$MACHINE_KEY" 2>/dev/null)"
        if [ "$perm" = "600" ]; then
            log_success "Nøkkelrettigheter OK (600)"
        else
            log_warn "Uventede rettigheter på privatnøkkel: $perm"
        fi
    else
        case "$status" in
            NEED_GUIDANCE|SUBMITTING|WAITING_FOR_CA)
                log_warn "Sertifikat ikke utstedt ennå — NDES-enrollment pågår ($status)"
                ;;
            *)
                log_error "Sertifikatfiler mangler (status: ${status:-ukjent})"
                ok=false
                ;;
        esac
    fi

    case "$status" in
        MONITORING)
            log_success "Certmonger sporer sertifikatet (MONITORING) — auto-fornyelse aktiv"
            ;;
        NEED_GUIDANCE|SUBMITTING|WAITING_FOR_CA)
            log_warn "Certmonger venter på NDES: $status"
            ;;
        *)
            log_error "Certmonger sporer ikke sertifikatet (status: ${status:-ukjent})"
            getcert list -i "$req_id" >> "$LOG_FILE" 2>&1 || true
            ok=false
            ;;
    esac

    if [ "$VPN_BUNDLE" = true ] && [ -n "${LAST_P12_PATH:-}" ] && [ -f "$LAST_P12_PATH" ]; then
        local p12_owner p12_perm
        p12_owner="$(stat -c '%U' "$LAST_P12_PATH" 2>/dev/null)"
        p12_perm="$(stat -c '%a' "$LAST_P12_PATH" 2>/dev/null)"
        if [ "$p12_owner" = "root" ] && [ "$p12_perm" = "600" ] \
           && [ "${LAST_P12_PATH#"$CERT_BASE_PATH"}" = "$LAST_P12_PATH" ]; then
            log_error ".p12 ligger i en hjemmekatalog men eies av root ($p12_perm)"
            log_error "  Brukeren kan ikke lese den: $LAST_P12_PATH"
            ok=false
        else
            log_success ".p12 klar for import: $LAST_P12_PATH (eier: $p12_owner, $p12_perm)"
            # Bekreft at pakka faktisk inneholder DET sertifikatet som er i bruk.
            local in_p12
            in_p12="$(openssl pkcs12 -in "$LAST_P12_PATH" -clcerts -nokeys \
                        -passin "pass:$(current_p12_password)" 2>/dev/null \
                      | openssl x509 -noout -fingerprint -sha256 2>/dev/null \
                      | sed 's/.*=//; s/://g' | tr 'A-F' 'a-f')"
            if [ -n "$in_p12" ] && [ "$in_p12" = "$(cert_fingerprint "$MACHINE_CERT")" ]; then
                log_success "  Innholdet matcher maskin-sertifikatet"
            elif [ -n "$in_p12" ]; then
                log_error "  .p12 inneholder et ANNET sertifikat enn $MACHINE_CERT"
                log_error "  Bygg om med: $INSTALL_PATH --vpn-bundle-only --force-p12"
                ok=false
            fi
        fi
    fi

    local c
    for c in "$WIRED_CONNECTION_NAME" "$WIFI_CONNECTION_NAME"; do
        if nm_conn_exists "$c"; then
            local dsm
            dsm="$(nm_get_field 802-1x.domain-suffix-match "$c")"
            if [ -n "$RADIUS_DOMAIN_SUFFIX" ] && [ -z "$dsm" ]; then
                log_warn "Profil '$c' mangler domain-suffix-match"
            else
                log_success "Profil finnes: $c${dsm:+ (server-match: $dsm)}"
            fi
        elif [ "$c" = "$WIFI_CONNECTION_NAME" ] \
             && ! nmcli -t -f TYPE device 2>/dev/null | grep -qxE 'wifi|802-11-wireless'; then
            log "Ingen WiFi-maskinvare — WiFi-profil ikke aktuell: $c"
        else
            log_warn "Profil ikke opprettet: $c"
        fi
    done

    # Nettverkstest mot noe som faktisk er relevant, ikke 8.8.8.8.
    local ndes_host="${SCEP_URL#https://}"; ndes_host="${ndes_host%%/*}"; ndes_host="${ndes_host%%:*}"
    if timeout 8 getent hosts "$ndes_host" >/dev/null 2>&1; then
        log_success "Nettverk/DNS fungerer ($ndes_host)"
    else
        log_warn "Ingen DNS-svar for $ndes_host (kan være forventet utenfor nettet)"
    fi

    if [ "$ok" = false ]; then
        log_error "Verifisering FEILET"
        return 1
    fi
    log_success "All verifisering OK"
    return 0
}

# ═════════════════════════════════════════════════════════════════════════════
# HOVEDFLYT
# ═════════════════════════════════════════════════════════════════════════════

init_logging
acquire_lock
init_workdir

detect_awk || exit 1

# ── Lettvektsmoduser: gjør bare én ting, hopper over hele utrullingen ───────
if [ "$RUN_MODE" = "status" ]; then
    show_status
    exit 0
fi

if [ "$RUN_MODE" = "fix-chain" ]; then
    if [ "$(id -u)" -ne 0 ]; then
        log_error "Må kjøres som root"
        exit 1
    fi
    detect_system_ca_bundle || exit 1
    run_chain_fixes || exit 1
    exit 0
fi

if [ "$RUN_MODE" = "cleanup-p12" ]; then
    if [ "$(id -u)" -ne 0 ]; then
        log_error "Må kjøres som root"
        exit 1
    fi
    cleanup_delivered_p12
    exit 0
fi

if [ "$RUN_MODE" = "forticlient-only" ]; then
    log_section "FortiClient (frittstående)"
    if [ "$(id -u)" -ne 0 ]; then
        log_error "Må kjøres som root"
        exit 1
    fi
    detect_system_ca_bundle || exit 1
    OS="$( . /etc/os-release 2>/dev/null; printf '%s' "${ID:-}" )"
    deploy_forticlient || exit 1
    exit 0
fi

if [ "$RUN_MODE" = "vpn-only" ]; then
    log_section "VPN-klientpakke (frittstående)"
    if [ "$(id -u)" -ne 0 ]; then
        log_error "Må kjøres som root"
        exit 1
    fi
    detect_system_ca_bundle || exit 1
    HOSTNAME_SHORT="$(hostname -s 2>/dev/null || hostname)"
    deploy_vpn_client_bundle || exit 1
    exit 0
fi

log_section "Enterprise Network Deployment"
log "Versjon: $SCRIPT_VERSION"
log "Testmodus: $TEST_MODE"
if [ "$CONFIG_LOADED" = true ]; then
    log "Konfigfil: $CONFIG_FILE"
else
    log_warn "Ingen konfigfil på $CONFIG_FILE — bruker innebygde standardverdier"
fi

preflight_checks

HOSTNAME_SHORT="$(hostname -s 2>/dev/null || hostname)"
if [ -z "$HOSTNAME_SHORT" ] || [ "$HOSTNAME_SHORT" = "localhost" ]; then
    log_error "Ugyldig maskinnavn ('$HOSTNAME_SHORT'). Sett et riktig hostname først."
    exit 1
fi
FQDN="${HOSTNAME_SHORT}.${DOMAIN_SUFFIX}"
REQUEST_ID="enterprise-8021x-${HOSTNAME_SHORT}"
log "Hostname: $HOSTNAME_SHORT"
log "FQDN:     $FQDN"

# OS-deteksjon i subshell — kilde ikke /etc/os-release direkte inn i skriptets
# navnerom (den setter bl.a. NAME, VERSION, HOME_URL og kan overskrive våre).
if [ -r /etc/os-release ]; then
    OS="$( . /etc/os-release 2>/dev/null; printf '%s' "${ID:-}" )"
    OS_VERSION="$( . /etc/os-release 2>/dev/null; printf '%s' "${VERSION_ID:-}" )"
    OS_NAME="$( . /etc/os-release 2>/dev/null; printf '%s' "${PRETTY_NAME:-}" )"
    log "OS: ${OS_NAME:-$OS $OS_VERSION}"
else
    log_error "Kan ikke lese /etc/os-release"
    exit 1
fi

case "$OS" in
    fedora|rhel|centos|rocky|almalinux|debian|ubuntu) : ;;
    *)
        log_error "Ikke støttet OS: $OS"
        exit 1
        ;;
esac

# ── [1/9] Pakker ──────────────────────────────────────────────────────────────

log_section "[1/9] Pakker"

install_packages() {
    case "$OS" in
        fedora|rhel|centos|rocky|almalinux)
            local pm="dnf"
            command -v dnf >/dev/null 2>&1 || pm="yum"
            run "Installerer pakker ($pm)" \
                "$pm" install -y certmonger NetworkManager wpa_supplicant openssl curl || return 1
            if [ "$P12_IMPORT_NSS" = true ]; then
                run_optional "Installerer nss-tools" "$pm" install -y nss-tools
            fi
            run_optional "Installerer NetworkManager-wifi" \
                "$pm" install -y NetworkManager-wifi
            ;;
        debian|ubuntu)
            export DEBIAN_FRONTEND=noninteractive
            run "apt-get update" apt-get update -qq || return 1
            run "Installerer pakker (apt)" \
                apt-get install -y --no-install-recommends \
                certmonger network-manager wpasupplicant openssl curl || return 1
            ;;
    esac
    return 0
}

if [ "$TEST_MODE" = true ]; then
    log "[TEST] Ville installert: certmonger, NetworkManager, wpa_supplicant, openssl, curl"
else
    install_packages || { log_error "Pakkeinstallasjon feilet"; exit 1; }

    run "Aktiverer certmonger" systemctl enable --now certmonger || true
    for _ in $(seq 1 20); do
        systemctl is-active --quiet certmonger && break
        sleep 1
    done
    if ! systemctl is-active --quiet certmonger; then
        log_error "certmonger startet ikke"
        systemctl status certmonger --no-pager >> "$LOG_FILE" 2>&1 || true
        exit 1
    fi
    if ! getcert list >/dev/null 2>&1; then
        log_error "certmonger svarer ikke på getcert"
        exit 1
    fi
    log_success "certmonger klar"
    install_logrotate
fi

# ── [2/9] NetworkManager som nettverksforvalter ───────────────────────────────

log_section "[2/9] NetworkManager"

if [ "$TEST_MODE" = true ]; then
    log "[TEST] Ville sikret at NetworkManager forvalter nettverket"
else
    require_cmd nmcli || { log_error "nmcli mangler etter installasjon"; exit 1; }

    if systemctl is-active --quiet systemd-networkd; then
        log_warn "systemd-networkd er aktiv — deaktiverer"
        log_warn "Hvis du er koblet til via SSH kan forbindelsen brytes."
        systemctl disable --now systemd-networkd >/dev/null 2>&1 || true
        record_state "SERVICE_STATE:systemd-networkd"
    fi

    if [ -d /etc/netplan ]; then
        netplan_files=(/etc/netplan/*.yaml /etc/netplan/*.yml)
        if [ ${#netplan_files[@]} -gt 0 ]; then
            NETPLAN_NM=/etc/netplan/01-network-manager-all.yaml
            if ! grep -rqs 'renderer:[[:space:]]*NetworkManager' /etc/netplan/; then
                log_warn "Netplan bruker ikke NetworkManager — bytter renderer"
                [ -f "$NETPLAN_NM" ] && backup_for_rollback "$NETPLAN_NM"
                cat > "$NETPLAN_NM" <<'NETPLAN'
network:
  version: 2
  renderer: NetworkManager
NETPLAN
                chmod 0600 "$NETPLAN_NM"
                [ -f "${RUNTIME_DIR}/backup$(printf '%s' "$NETPLAN_NM" | tr '/' '_')" ] \
                    || record_state "FILE_CREATED:$NETPLAN_NM"
                command -v netplan >/dev/null 2>&1 && netplan apply >> "$LOG_FILE" 2>&1 || true
                log_success "Netplan satt til NetworkManager"
            fi
        fi
    fi

    if ! systemctl is-active --quiet NetworkManager; then
        systemctl enable NetworkManager >/dev/null 2>&1 || true
        systemctl start NetworkManager >/dev/null 2>&1 || true
        for _ in $(seq 1 30); do
            systemctl is-active --quiet NetworkManager && break
            sleep 1
        done
    fi
    if ! systemctl is-active --quiet NetworkManager; then
        log_error "NetworkManager startet ikke"
        exit 1
    fi
    nmcli general status >/dev/null 2>&1 || { log_error "nmcli svarer ikke"; exit 1; }
    log_success "NetworkManager klar"
fi

# ── [3/9] Nåværende nettverksstatus ───────────────────────────────────────────

log_section "[3/9] Nåværende nettverksstatus"

if [ "$TEST_MODE" = true ]; then
    log "[TEST] Ville registrert aktive kablet-/WiFi-tilkoblinger"
else
    ACTIVE_CONNECTIONS="$(nmcli -t -f NAME,TYPE,DEVICE connection show --active 2>/dev/null || true)"
    if [ -n "$ACTIVE_CONNECTIONS" ]; then
        log "Aktive tilkoblinger:"
        while IFS= read -r line; do
            [ -z "$line" ] && continue
            log "  - $(printf '%s' "$line" | nm_unescape)"
        done <<< "$ACTIVE_CONNECTIONS"
    else
        log "Ingen aktive tilkoblinger"
    fi

    ACTIVE_WIRED_CONNECTION="$(grep -E ':(ethernet|802-3-ethernet):' <<< "$ACTIVE_CONNECTIONS" \
        | head -1 | sed 's/:[^:]*:[^:]*$//' | nm_unescape || true)"
    ACTIVE_WIFI_CONNECTION="$(grep -E ':(wifi|802-11-wireless):' <<< "$ACTIVE_CONNECTIONS" \
        | head -1 | sed 's/:[^:]*:[^:]*$//' | nm_unescape || true)"

    [ -n "$ACTIVE_WIRED_CONNECTION" ] && log "Aktiv kablet: $ACTIVE_WIRED_CONNECTION"
    [ -n "$ACTIVE_WIFI_CONNECTION" ]  && log "Aktiv WiFi:   $ACTIVE_WIFI_CONNECTION"
fi

# ── [4/9] SHA-1-kompatibilitet ────────────────────────────────────────────────

log_section "[4/9] SHA-1-kompatibilitet for SCEP"

if [ "$TEST_MODE" = true ]; then
    log "[TEST] SHA1_MODE=$SHA1_MODE — ville tilpasset SHA-1 for certmonger"
else
    ensure_sha1_compat || exit 1
fi

# ── [5/9] SCEP-enrollment ─────────────────────────────────────────────────────

log_section "[5/9] SCEP-enrollment"

if [ "$TEST_MODE" = true ]; then
    log "[TEST] Ville opprettet $CERT_BASE_PATH (0700)"
    log "[TEST] Ville konfigurert SCEP CA '$CA_NAME' mot $SCEP_URL"
    log "[TEST] Ville verifisert CA-pinning mot $PIN_FILE"
    log "[TEST] Ville bedt om maskin-sertifikat for: $FQDN"
else
    install -d -m 0700 "$CERT_BASE_PATH"

    NEED_SCEP_RECONFIG=false
    if getcert list-cas 2>/dev/null | grep -q "^CA '$CA_NAME'"; then
        CA_HELPER_LINE="$(getcert list-cas -c "$CA_NAME" 2>/dev/null | grep 'helper-location:' || true)"
        EXISTING_STATUS="$(cert_status "$REQUEST_ID")"

        case "$EXISTING_STATUS" in
            NEED_SCEP_ENCRYPTION_CERT|CA_UNCONFIGURED|CA_UNREACHABLE)
                log_warn "Eksisterende forespørsel har status $EXISTING_STATUS — rekonfigurerer"
                NEED_SCEP_RECONFIG=true
                ;;
        esac

        if [ "$NEED_SCEP_RECONFIG" = false ]; then
            if ! grep -qE 'ca-bundle\.crt|ca-certificates\.crt|tls-ca-bundle\.pem|ssl/cert\.pem' <<< "$CA_HELPER_LINE"; then
                log_warn "CA-config bruker ikke system-CA-bundle — oppgraderer"
                NEED_SCEP_RECONFIG=true
            elif grep -q 'ca_encryption_cert' <<< "$CA_HELPER_LINE"; then
                log_warn "CA-config har ca_encryption_cert — rekonfigurerer"
                NEED_SCEP_RECONFIG=true
            else
                log "SCEP CA allerede konfigurert i riktig format"
            fi
        fi

        if [ "$NEED_SCEP_RECONFIG" = true ]; then
            getcert stop-tracking -i "$REQUEST_ID" >/dev/null 2>&1 || true
            getcert remove-ca -c "$CA_NAME" >/dev/null 2>&1 || true
            sleep 2
        fi
    else
        NEED_SCEP_RECONFIG=true
    fi

    if [ "$NEED_SCEP_RECONFIG" = true ]; then
        configure_scep_ca || { log_error "SCEP CA-konfigurasjon feilet"; exit 1; }
    fi

    # ── Rydd bort forespørsler som kolliderer med våre filer ──────────────────
    log "Ser etter gamle sertifikatforespørsler..."
    ALL_REQUESTS="$(getcert list 2>/dev/null | grep 'Request ID' | sed "s/.*Request ID '//; s/'.*//" || true)"
    CLEANED=0
    if [ -n "$ALL_REQUESTS" ]; then
        while IFS= read -r RID; do
            [ -z "$RID" ] && continue
            [ "$RID" = "$REQUEST_ID" ] && continue

            DETAILS="$(getcert list -i "$RID" 2>/dev/null || true)"
            RCERT="$(grep -m1 'certificate:' <<< "$DETAILS" | sed "s/.*location='//; s/'.*//" || true)"
            RKEY="$(grep -m1 'key pair' <<< "$DETAILS"    | sed "s/.*location='//; s/'.*//" || true)"
            RCA="$(grep -m1 '^[[:space:]]*CA:' <<< "$DETAILS" | "$AWK" '{print $2}' || true)"
            RSUBJ="$(grep -m1 '^[[:space:]]*subject:' <<< "$DETAILS" | cut -d: -f2- || true)"

            if [ "$RCERT" = "$MACHINE_CERT" ] || [ "$RKEY" = "$MACHINE_KEY" ]; then
                log_warn "  Fjerner kolliderende forespørsel: $RID"
                getcert stop-tracking -i "$RID" >/dev/null 2>&1 || true
                CLEANED=$((CLEANED + 1))
            elif [ "$RCA" = "$CA_NAME" ] && [[ "$RSUBJ" == *"$HOSTNAME_SHORT"* ]]; then
                log_warn "  Fjerner gammel forespørsel: $RID"
                getcert stop-tracking -i "$RID" >/dev/null 2>&1 || true
                CLEANED=$((CLEANED + 1))
            fi
        done <<< "$ALL_REQUESTS"
    fi
    [ "$CLEANED" -gt 0 ] && log_success "Ryddet $CLEANED gammel(e) forespørsel(er)"

    # ── Be om sertifikat ──────────────────────────────────────────────────────
    CERT_ENROLLED=false
    if [ "$(cert_status "$REQUEST_ID")" = "MONITORING" ]; then
        if [ -s "$MACHINE_CERT" ] && [ -f "$MACHINE_KEY" ]; then
            log "Sertifikat allerede utstedt og spores"
            CERT_ENROLLED=true
        else
            log_warn "Sporing finnes, men filene mangler — starter på nytt"
            getcert stop-tracking -i "$REQUEST_ID" >/dev/null 2>&1 || true
        fi
    fi

    if [ "$CERT_ENROLLED" = false ]; then
        getcert stop-tracking -i "$REQUEST_ID" >/dev/null 2>&1 || true
        rm -f "$MACHINE_CERT" "$MACHINE_KEY"

        log "Ber om sertifikat for: $FQDN"
        GETCERT_ARGS=(
            request
            -c "$CA_NAME"
            -I "$REQUEST_ID"
            -k "$MACHINE_KEY"
            -f "$MACHINE_CERT"
            -N "CN=$FQDN"
            -D "$FQDN"
            -r                       # auto-forny
        )
        if [ "$RENEW_HOOK" = true ] && [ "$VPN_BUNDLE" = true ]; then
            install_renew_hook && GETCERT_ARGS+=(-C "$RENEW_HOOK_PATH")
        fi
        [ -n "$KEY_SIZE" ] && GETCERT_ARGS+=(-g "$KEY_SIZE")
        if [ "$REQUEST_EKU" = true ]; then
            GETCERT_ARGS+=(-u digitalSignature -u keyEncipherment -U id-kp-clientAuth)
        fi

        REQ_OUT="$(getcert "${GETCERT_ARGS[@]}" 2>&1)"; REQ_RC=$?
        printf '%s\n' "$REQ_OUT" >> "$LOG_FILE"
        log "getcert: $REQ_OUT"

        if [ "$REQ_RC" -ne 0 ] || grep -qiE 'already used|error|failed' <<< "$REQ_OUT"; then
            log_error "getcert request feilet: $REQ_OUT"
            exit 1
        fi
        record_state "CERT_REQUESTED:$REQUEST_ID"

        log "Venter på sertifikat (maks ${ENROLL_TIMEOUT}s)..."
        ELAPSED=0
        STATUS=""
        RESUBMITS=0
        RECOVERY_TRIED=false
        UNREACHABLE_RETRIES=0

        # Felles gjenopprettingsforsøk for de statusene som i praksis skyldes
        # SHA-1-blokkering. Returnerer 0 hvis noe ble endret og det er verdt
        # å prøve på nytt.
        attempt_enrollment_recovery() {
            [ "$RECOVERY_TRIED" = true ] && return 1
            RECOVERY_TRIED=true
            log_warn "Forsøker gjenoppretting: eskalerer SHA-1-policy"
            if maybe_escalate_sha1; then
                sleep 3
                getcert resubmit -i "$REQUEST_ID" >/dev/null 2>&1 || true
                log "Forespørselen er sendt inn på nytt"
                return 0
            fi
            log_warn "Ingen SHA-1-eskalering tilgjengelig (SHA1_MODE=$SHA1_MODE)"
            return 1
        }
        while [ "$ELAPSED" -lt "$ENROLL_TIMEOUT" ]; do
            sleep 3
            ELAPSED=$((ELAPSED + 3))
            STATUS="$(cert_status "$REQUEST_ID")"

            case "$STATUS" in
                MONITORING)
                    log_success "Sertifikat utstedt!"
                    break
                    ;;
                CA_REJECTED)
                    # Ekte avvisning fra CA-en. Ikke noe å gjenopprette.
                    log_error "NDES AVVISTE forespørselen. Sjekk enrollment-rettigheter og mal."
                    diagnose_scep_failure "$REQUEST_ID"
                    exit 1
                    ;;
                CA_UNREACHABLE)
                    # GetCACert lyktes tidligere i kjøringen, så endepunktet
                    # finnes. CA_UNREACHABLE her betyr som regel at PKCSReq
                    # ikke lot seg signere (SHA-1), eller at certmonger-
                    # tjenesten mangler proxy. Prøv gjenoppretting før vi gir opp.
                    if attempt_enrollment_recovery; then
                        ELAPSED=0
                        continue
                    fi
                    UNREACHABLE_RETRIES=$((UNREACHABLE_RETRIES + 1))
                    if [ "$UNREACHABLE_RETRIES" -le 2 ]; then
                        log_warn "CA_UNREACHABLE — nytt forsøk ($UNREACHABLE_RETRIES/2)"
                        sleep 10
                        getcert resubmit -i "$REQUEST_ID" >/dev/null 2>&1 || true
                        continue
                    fi
                    log_error "CA_UNREACHABLE — certmonger når ikke SCEP-endepunktet."
                    diagnose_scep_failure "$REQUEST_ID"
                    exit 1
                    ;;
                CA_UNCONFIGURED|NEED_SCEP_ENCRYPTION_CERT)
                    if attempt_enrollment_recovery; then
                        ELAPSED=0
                        continue
                    fi
                    log_error "$STATUS — RA-sertifikatproblem i certmonger-config."
                    diagnose_scep_failure "$REQUEST_ID"
                    exit 1
                    ;;
                NEED_GUIDANCE)
                    # Eksponentiell backoff i stedet for resubmit hvert 30. sekund.
                    if [ "$ELAPSED" -ge $(( 30 * (1 << RESUBMITS) )) ] && [ "$RESUBMITS" -lt 3 ]; then
                        RESUBMITS=$((RESUBMITS + 1))
                        log "NEED_GUIDANCE — resubmit #$RESUBMITS"
                        getcert resubmit -i "$REQUEST_ID" >/dev/null 2>&1 || true
                    fi
                    ;;
                SUBMITTING|WAITING_FOR_CA|GENERATING_KEY_PAIR|GENERATING_CSR)
                    ;;
                *)
                    [ $((ELAPSED % 15)) -eq 0 ] && log "Status: ${STATUS:-ukjent} (venter...)"
                    ;;
            esac
        done

        case "$STATUS" in
            MONITORING) ;;
            NEED_GUIDANCE|SUBMITTING|WAITING_FOR_CA)
                log_warn "Enrollment pågår fortsatt (status: $STATUS)."
                log_warn "Certmonger poller videre i bakgrunnen — profilene settes opp uansett."
                getcert list -i "$REQUEST_ID" >> "$LOG_FILE" 2>&1
                ;;
            *)
                log_error "Enrollment feilet. Sluttstatus: ${STATUS:-ukjent}"
                diagnose_scep_failure "$REQUEST_ID"
                exit 1
                ;;
        esac
    fi

    if [ -s "$MACHINE_CERT" ] && [ -f "$MACHINE_KEY" ]; then
        chmod 0644 "$MACHINE_CERT"
        chmod 0600 "$MACHINE_KEY"
        chown root:root "$MACHINE_CERT" "$MACHINE_KEY" 2>/dev/null || true

        if openssl pkey -in "$MACHINE_KEY" -noout >/dev/null 2>&1; then
            log_success "Privatnøkkel lesbar uten passfrase"
        else
            log_error "Privatnøkkel er ikke lesbar eller har passfrase"
            exit 1
        fi
        log "Subject: $(cert_subject "$MACHINE_CERT")"
        log "Utløper: $(openssl x509 -in "$MACHINE_CERT" -noout -enddate | sed 's/notAfter=//')"
    else
        log_warn "Sertifikatfiler ikke tilgjengelige ennå (enrollment pågår)"
    fi
fi

# ── [6/9] CA-kjede for 802.1X ─────────────────────────────────────────────────

log_section "[6/9] CA-kjede for 802.1X"

if [ "$TEST_MODE" = true ]; then
    log "[TEST] Ville skrevet CA-kjede til $CA_CERT"
else
    if [ ! -s "$CA_CERT" ]; then
        if [ -s "$PERM_CA_CHAIN" ]; then
            install -m 0644 "$PERM_CA_CHAIN" "$CA_CERT"
            log_success "CA-kjede kopiert fra verifisert SCEP-bundle"
        else
            log "Henter CA-kjede via GetCACert..."
            P7B="$WORKDIR/ndes-ca-8021x.p7b"
            if http_get "${SCEP_URL}?operation=GetCACert&message=0" "$P7B" && [ -s "$P7B" ]; then
                openssl pkcs7 -in "$P7B" -inform DER -print_certs -out "$CA_CERT" 2>> "$LOG_FILE" || true
            fi
        fi

        if [ ! -s "$CA_CERT" ]; then
            log_error "Klarte ikke etablere CA-kjede for 802.1X"
            exit 1
        fi
        chmod 0644 "$CA_CERT"
    else
        log "CA-kjede finnes allerede: $CA_CERT"
    fi

    # 802.1X-CA-fila skal inneholde CA-er, ikke endepunkt-sertifikater.
    CA_IN_FILE="$(grep -c 'BEGIN CERTIFICATE' "$CA_CERT" || true)"
    log "CA-kjede: ${CA_IN_FILE:-0} sertifikat(er) i $CA_CERT"
fi

# ── [7/9] Nedprioriter gamle profiler / bevar eksisterende ────────────────────

log_section "[7/9] Profilprioriteringer"

if [ "$TEST_MODE" = true ]; then
    log "[TEST] Ville nedprioritert gamle '${OLD_PROFILE_MATCH}'-WiFi-profiler til $OLD_INDRA_PRIORITY"
    log "[TEST] Ville satt aktive fallback-profiler til $EXISTING_FALLBACK_PRIORITY"
else
    ALL_WIFI="$(nmcli -t -f NAME,TYPE connection show 2>/dev/null | grep ':wifi$' \
        | sed 's/:wifi$//' | nm_unescape || true)"
    DEPRIORITIZED=0
    if [ -n "$ALL_WIFI" ]; then
        while IFS= read -r WNAME; do
            [ -z "$WNAME" ] && continue
            [ "$WNAME" = "$WIFI_CONNECTION_NAME" ] && continue
            WLOWER="$(printf '%s' "$WNAME" | tr '[:upper:]' '[:lower:]')"
            if [[ "$WLOWER" == *"$OLD_PROFILE_MATCH"* ]]; then
                log "  Nedprioriterer: $WNAME"
                nmcli connection modify "$WNAME" \
                    connection.autoconnect-priority "$OLD_INDRA_PRIORITY" \
                    connection.autoconnect yes >> "$LOG_FILE" 2>&1 \
                    && DEPRIORITIZED=$((DEPRIORITIZED + 1))
            fi
        done <<< "$ALL_WIFI"
    fi
    [ "$DEPRIORITIZED" -gt 0 ] && log_success "Nedprioriterte $DEPRIORITIZED profil(er)"

    for PRESERVE in "$ACTIVE_WIRED_CONNECTION" "$ACTIVE_WIFI_CONNECTION"; do
        [ -z "$PRESERVE" ] && continue
        [ "$PRESERVE" = "$WIRED_CONNECTION_NAME" ] && continue
        [ "$PRESERVE" = "$WIFI_CONNECTION_NAME" ] && continue
        log "Bevarer som fallback: $PRESERVE"
        nmcli connection modify "$PRESERVE" \
            connection.autoconnect-priority "$EXISTING_FALLBACK_PRIORITY" \
            connection.autoconnect yes >> "$LOG_FILE" 2>&1 || true
    done
fi

# ── [8/9] 802.1X-profiler ─────────────────────────────────────────────────────

log_section "[8/9] 802.1X-profiler"

# Felles 802.1X-argumenter inkl. server-identitetskontroll.
build_8021x_args() {
    NM_8021X_ARGS=(
        802-1x.eap "$EAP_METHOD"
        802-1x.identity "host/$FQDN"
        802-1x.client-cert "file://$MACHINE_CERT"
        802-1x.private-key "file://$MACHINE_KEY"
        802-1x.private-key-password-flags 4
        802-1x.ca-cert "file://$CA_CERT"
    )
    if [ -n "$RADIUS_DOMAIN_SUFFIX" ]; then
        NM_8021X_ARGS+=(802-1x.domain-suffix-match "$RADIUS_DOMAIN_SUFFIX")
    fi
}

# Sjekk om en eksisterende profil allerede har riktig innhold.
profile_is_current() {
    local name="$1"
    [ "$(nm_get_field 802-1x.client-cert "$name")" = "file://$MACHINE_CERT" ] || return 1
    [ "$(nm_get_field 802-1x.ca-cert "$name")" = "file://$CA_CERT" ] || return 1
    if [ -n "$RADIUS_DOMAIN_SUFFIX" ]; then
        [ "$(nm_get_field 802-1x.domain-suffix-match "$name")" = "$RADIUS_DOMAIN_SUFFIX" ] || return 1
    fi
    return 0
}

if [ "$TEST_MODE" = true ]; then
    log "[TEST] Ville opprettet '$WIRED_CONNECTION_NAME' (prioritet $WIRED_PRIORITY)"
    log "[TEST] Ville opprettet '$WIFI_CONNECTION_NAME' på SSID $WIFI_SSID (prioritet $WIFI_PRIORITY)"
    log "[TEST] private-key-password-flags: 4 (not-required)"
    [ -n "$RADIUS_DOMAIN_SUFFIX" ] \
        && log "[TEST] 802-1x.domain-suffix-match: $RADIUS_DOMAIN_SUFFIX" \
        || log "[TEST] ADVARSEL: ingen domain-suffix-match satt"
else
    build_8021x_args

    # ---- Kablet ----
    WIRED_INTERFACES="$(nmcli -t -f DEVICE,TYPE device 2>/dev/null \
        | grep -E ':(ethernet|802-3-ethernet)$' | cut -d: -f1 || true)"

    if [ -z "$WIRED_INTERFACES" ]; then
        log "Ingen kablede grensesnitt funnet"
    else
        WIRED_INTERFACE="$(head -1 <<< "$WIRED_INTERFACES")"
        log "Kablet grensesnitt: $WIRED_INTERFACE"

        SKIP_WIRED_ACTIVATION=false
        if [ -n "$ACTIVE_WIRED_CONNECTION" ] && [ "$ACTIVE_WIRED_CONNECTION" != "$WIRED_CONNECTION_NAME" ]; then
            log_warn "Grensesnittet er i bruk av '$ACTIVE_WIRED_CONNECTION' — avbryter ikke"
            SKIP_WIRED_ACTIVATION=true
        fi

        if nm_conn_exists "$WIRED_CONNECTION_NAME"; then
            if profile_is_current "$WIRED_CONNECTION_NAME"; then
                log "Kablet 802.1X-profil er allerede riktig konfigurert"
            else
                log "Oppdaterer eksisterende kablet profil"
                nmcli connection modify "$WIRED_CONNECTION_NAME" \
                    connection.autoconnect-priority "$WIRED_PRIORITY" \
                    connection.autoconnect yes \
                    "${NM_8021X_ARGS[@]}" >> "$LOG_FILE" 2>&1 \
                    || log_warn "Kunne ikke oppdatere profilen"
            fi
        else
            if nmcli connection add \
                type ethernet \
                con-name "$WIRED_CONNECTION_NAME" \
                ifname "$WIRED_INTERFACE" \
                autoconnect yes \
                connection.autoconnect-priority "$WIRED_PRIORITY" \
                "${NM_8021X_ARGS[@]}" \
                ipv4.method auto \
                ipv6.method auto >> "$LOG_FILE" 2>&1
            then
                record_state "CONNECTION_CREATED:$WIRED_CONNECTION_NAME"
                log_success "Kablet 802.1X-profil opprettet"
            else
                log_error "Klarte ikke opprette kablet profil"
                exit 1
            fi
        fi

        if [ "$SKIP_WIRED_ACTIVATION" = false ]; then
            if nmcli connection up "$WIRED_CONNECTION_NAME" >> "$LOG_FILE" 2>&1; then
                log_success "Kablet 802.1X aktivert"
            else
                log_warn "Kunne ikke aktivere nå — aktiveres automatisk på 802.1X-nett"
            fi
        else
            log "Profil klar — aktiveres automatisk ved behov"
        fi
    fi

    # ---- Sørg for at ethernet forvaltes av NM ----
    if [[ "$OS" == "debian" || "$OS" == "ubuntu" ]] && [ -f /etc/network/interfaces ]; then
        if grep -qE '^[[:space:]]*(auto|allow-hotplug|iface)[[:space:]]+e(ns|th|np)[0-9]' /etc/network/interfaces; then
            log_warn "Ethernet konfigurert i /etc/network/interfaces — deaktiverer"
            log_warn "Nettverket kan bli kortvarig utilgjengelig."
            backup_for_rollback /etc/network/interfaces
            sed -i -E 's/^([[:space:]]*(auto|allow-hotplug|iface)[[:space:]]+e(ns|th|np)[0-9])/# DISABLED-BY-DEPLOY: \1/' \
                /etc/network/interfaces
            systemctl stop networking >/dev/null 2>&1 || true
            systemctl restart NetworkManager >/dev/null 2>&1 || true
            sleep 5
            log_success "Ethernet fjernet fra ifupdown"
        fi
    fi

    if [ -n "$WIRED_INTERFACES" ]; then
        while IFS= read -r WIF; do
            [ -z "$WIF" ] && continue
            IF_STATE="$(nmcli -t -f DEVICE,STATE device status 2>/dev/null \
                | grep "^${WIF}:" | cut -d: -f2 || true)"
            if [ "$IF_STATE" = "unmanaged" ]; then
                log_warn "Grensesnitt $WIF er unmanaged — retter"
                nmcli device set "$WIF" managed yes >> "$LOG_FILE" 2>&1 || true
                sleep 2
            fi
        done <<< "$WIRED_INTERFACES"
    fi

    # ---- WiFi ----
    WIFI_INTERFACES="$(nmcli -t -f DEVICE,TYPE device 2>/dev/null \
        | grep -E ':(wifi|802-11-wireless)$' | cut -d: -f1 || true)"

    if [ -z "$WIFI_INTERFACES" ]; then
        log "Ingen WiFi-grensesnitt funnet"
    else
        WIFI_INTERFACE="$(head -1 <<< "$WIFI_INTERFACES")"
        nmcli radio wifi on >/dev/null 2>&1 || true
        sleep 2

        SKIP_WIFI_ACTIVATION=false
        if [ -n "$ACTIVE_WIFI_CONNECTION" ] && [ "$ACTIVE_WIFI_CONNECTION" != "$WIFI_CONNECTION_NAME" ]; then
            log_warn "WiFi i bruk av '$ACTIVE_WIFI_CONNECTION' — avbryter ikke"
            SKIP_WIFI_ACTIVATION=true
        fi

        nmcli device wifi rescan ifname "$WIFI_INTERFACE" >/dev/null 2>&1 || true
        sleep 4

        # Eksakt SSID-match (v3.5.9 brukte grep -qw, som feiler på SSID med
        # mellomrom eller delstreng-treff).
        SSID_HIDDEN="yes"
        if nmcli -t -f SSID device wifi list ifname "$WIFI_INTERFACE" 2>/dev/null \
            | nm_unescape | grep -Fxq "$WIFI_SSID"; then
            SSID_HIDDEN="no"
            log_success "SSID '$WIFI_SSID' er synlig"
        else
            log "SSID '$WIFI_SSID' ikke synlig (skjult eller utenfor rekkevidde)"
        fi

        if nm_conn_exists "$WIFI_CONNECTION_NAME"; then
            if profile_is_current "$WIFI_CONNECTION_NAME"; then
                log "WiFi 802.1X-profil er allerede riktig konfigurert"
            else
                log "Oppdaterer eksisterende WiFi-profil"
                nmcli connection modify "$WIFI_CONNECTION_NAME" \
                    connection.autoconnect-priority "$WIFI_PRIORITY" \
                    connection.autoconnect yes \
                    wifi.hidden "$SSID_HIDDEN" \
                    wifi-sec.key-mgmt wpa-eap \
                    "${NM_8021X_ARGS[@]}" >> "$LOG_FILE" 2>&1 \
                    || log_warn "Kunne ikke oppdatere WiFi-profilen"
            fi
        else
            if nmcli connection add \
                type wifi \
                con-name "$WIFI_CONNECTION_NAME" \
                ifname "$WIFI_INTERFACE" \
                ssid "$WIFI_SSID" \
                autoconnect yes \
                connection.autoconnect-priority "$WIFI_PRIORITY" \
                wifi.hidden "$SSID_HIDDEN" \
                wifi-sec.key-mgmt wpa-eap \
                "${NM_8021X_ARGS[@]}" \
                ipv4.method auto \
                ipv6.method auto >> "$LOG_FILE" 2>&1
            then
                record_state "CONNECTION_CREATED:$WIFI_CONNECTION_NAME"
                log_success "WiFi 802.1X-profil opprettet"
            else
                log_error "Klarte ikke opprette WiFi-profil"
                exit 1
            fi
        fi

        if [ "$SKIP_WIFI_ACTIVATION" = false ]; then
            if nmcli connection up "$WIFI_CONNECTION_NAME" >> "$LOG_FILE" 2>&1; then
                log_success "WiFi aktivert"
            else
                log_warn "Kunne ikke aktivere nå — aktiveres når nettet er i rekkevidde"
            fi
        else
            log "Profil klar — aktiveres når nettet er i rekkevidde"
        fi
    fi
fi

# ── [8C/9] VPN-klientpakke ────────────────────────────────────────────────────

deploy_vpn_client_bundle || log_warn "VPN-klientpakka ble ikke fullført"

# ── [8D/9] FortiClient ────────────────────────────────────────────────────────

deploy_forticlient || log_warn "FortiClient-stadiet ble ikke fullført"

# ── [9/9] Verifisering ────────────────────────────────────────────────────────

VERIFY_RC=0
verify_deployment || VERIFY_RC=$?

if [ "$TEST_MODE" = true ]; then
    echo ""
    echo "=== TEST MODE — OPPSUMMERING (v$SCRIPT_VERSION) ==="
    if [ "$CONFIG_LOADED" = true ]; then
    echo "  Konfigfil ................ $CONFIG_FILE (lastet)"
    else
    echo "  Konfigfil ................ IKKE funnet — bruker innebygde verdier"
    echo "                             forventet: $CONFIG_FILE"
    fi
    echo "  SCEP-URL ................. $SCEP_URL"
    echo "  TLS-verifisering ......... $([ "$ALLOW_INSECURE_TLS" = true ] && echo 'AV (usikkert)' || echo 'PÅ')"
    echo "  CA-pinning ............... $CA_PINNING (fil: $PIN_FILE)"
    echo "  SHA-1-modus .............. $SHA1_MODE"
    echo "  Maskin-FQDN .............. $FQDN"
    echo "  Kablet profil ............ $WIRED_CONNECTION_NAME (prio $WIRED_PRIORITY)"
    echo "  WiFi-profil .............. $WIFI_CONNECTION_NAME / $WIFI_SSID (prio $WIFI_PRIORITY)"
    echo "  RADIUS server-match ...... ${RADIUS_DOMAIN_SUFFIX:-<ingen — frarådes>}"
    echo "  Trust store-installasjon . $INSTALL_CA_IN_TRUST_STORE (kun CA, ikke RA)"
    echo "  VPN-klientpakke .......... $VPN_BUNDLE"
    if [ "$VPN_BUNDLE" = true ]; then
    echo "    .p12-navn .............. $P12_FILENAME"
    echo "    Passordmodus ........... $P12_PASSWORD_MODE"
    echo "    PKCS#12-kompatmodus .... $P12_COMPAT"
    echo "    Ekstra anchors ......... ${#EXTRA_TRUST_ANCHORS[@]}"
    echo "    .p12-plassering ........ ${P12_TARGET_USER:-systemvidt ($CERT_BASE_PATH)}${P12_TARGET_SUBDIR:+ / $P12_TARGET_SUBDIR}"
    echo "    Fornyelseshook ......... $RENEW_HOOK"
    echo "    Utelatte kontoer ....... ${P12_EXCLUDE_USERS:-<ingen>}"
    if [ "$P12_RETENTION_DAYS" -gt 0 ] 2>/dev/null; then
    echo "    Oppbevaring av .p12 .... ryddes etter ${P12_RETENTION_DAYS} dager"
    else
    echo "    Oppbevaring av .p12 .... beholdes (FortiClient kan lese stien)"
    fi
    echo "    NSS-import ............. $P12_IMPORT_NSS"
    echo "    Kjedereparasjon ........ ${#FIX_CHAIN_HOSTS[@]} vert(er)"
    if [ "${#EXTRA_TRUST_ANCHORS[@]}" -gt 0 ]; then
    for ANCHOR_LINE in "${EXTRA_TRUST_ANCHORS[@]}"; do
    echo "    Mellom-CA installeres .. ${ANCHOR_LINE%%|*}"
    done
    else
    echo "    Mellom-CA .............. forvaltes utenfor skriptet (EXTRA_TRUST_ANCHORS=())"
    fi
    echo "    VPN-kjede kontrolleres . $VPN_CHAIN_CHECK (forventer: ${VPN_CHAIN_EXPECT_ISSUER:-<ingen>})"
    fi
    echo "  FortiClient .............. ${FORTICLIENT_RPM:-<ikke konfigurert>}"
    if [ -n "$FORTICLIENT_RPM" ]; then
    echo "    Forventet versjon ...... ${FORTICLIENT_EXPECTED_VERSION:-<uspesifisert>}"
    echo "    Nedgradering tillatt ... $FORTICLIENT_ALLOW_DOWNGRADE"
    echo "    SHA-256-pin ............ ${FORTICLIENT_RPM_SHA256:+satt}${FORTICLIENT_RPM_SHA256:-<ikke satt>}"
    echo "    EMS-registrering ....... ${EMS_INVITATION_CODE:+invitasjonskode}${EMS_SERVER:+$EMS_SERVER}"
    echo "    Versjonslås ............ $FORTICLIENT_VERSIONLOCK"
    fi
    echo "  AWK ...................... ${AWK:-<ingen>}"
    echo ""
    echo "Kjør uten --test for å deploye."
    exit 0
fi

# Rollback skal ikke utløses av at enrollment fortsatt er underveis —
# det er en forventet tilstand, ikke en feil.
rm -f "$STATE_FILE" 2>/dev/null || true

echo ""
if [ "$VERIFY_RC" -eq 0 ]; then
    echo "OK: 802.1X utrullet på $(hostname). Logg: $LOG_FILE"
    if [ "$VPN_BUNDLE" = true ] && [ -n "${LAST_P12_PATH:-}" ] && [ -f "${LAST_P12_PATH}" ]; then
        echo ""
        echo "  Importer i FortiClient:  ${LAST_P12_PATH}"
        echo "  Eier:                    $(stat -c '%U' "${LAST_P12_PATH}" 2>/dev/null)"
        if [ "$P12_PASSWORD_MODE" = "fixed" ]; then
            echo "  Kode:                    ${P12_PASSWORD}"
        else
            echo "  Kode:                    se ${P12_PASSWORD_FILE}"
        fi
        if [ "$P12_RETENTION_DAYS" -gt 0 ] 2>/dev/null; then
            echo "  Fila ryddes bort automatisk om ${P12_RETENTION_DAYS} dager."
        else
            echo "  La fila ligge — FortiClient leser den ved hver tilkobling."
        fi
    fi
else
    echo "DELVIS: Utrulling gjennomført, men verifisering hadde merknader."
    echo "        Se $LOG_FILE. Certmonger fortsetter i bakgrunnen."
fi
exit 0

# ═════════════════════════════════════════════════════════════════════════════
# CHANGELOG 3.5.9 -> 4.0.0
# ═════════════════════════════════════════════════════════════════════════════
#
# SIKKERHET
#  1. curl -k fjernet. All HTTPS-henting verifiserer nå TLS mot systemets
#     CA-bundle (--proto '=https', --tlsv1.2, --fail). Tidligere ble selve
#     CA-kjeden som brukes til 802.1X-servervalidering hentet over en
#     uautentisert kanal — en MITM kunne bytte den ut.
#     Nødutgang: ALLOW_INSECURE_TLS=true (logger høylytt advarsel).
#  2. CA-pinning (TOFU) mot /etc/pki/802.1x/ca-pins.sha256. Skriptet nekter
#     å fortsette hvis NDES plutselig leverer en annen CA. --update-pins
#     ved planlagt CA-fornyelse.
#  3. 802-1x.domain-suffix-match settes på begge profiler. Uten dette
#     godtar klienten ethvert servercert utstedt av CA-en, dvs. RADIUS-
#     impersonering er mulig innenfor samme PKI.
#  4. RA-sertifikatet legges ikke lenger inn som trust anchor i systemets
#     trust store (det er et endepunkt-sertifikat). Gammel ndes-ra.crt
#     ryddes bort.
#  5. Faste /tmp-stier erstattet med mktemp -d 0700. De gamle stiene var
#     forutsigbare og skrivbare for andre — symlink-angrep mot root.
#  6. Tilstandsfila flyttet fra /tmp til /run/... 0700. Den gamle kunne
#     endres av lokale brukere, og rollback ville da slette vilkårlige
#     NM-profiler eller overskrive vilkårlige filer.
#  7. eval "$command" erstattet med argumentarray (run()).
#  8. Global crypto policy svekkes ikke lenger som standard. SHA1_MODE=auto
#     legger en systemd drop-in som gir SHA-1 kun til certmonger, og
#     eskalerer til global policy bare hvis SCEP faktisk feiler.
#  9. CRYPTO_POLICY_CHANGED har nå en rollback-handler (den ble registrert,
#     men aldri rullet tilbake i 3.5.9).
# 10. Loggfiler opprettes med install -m 0600 (ingen race mellom touch og
#     chmod) og symlinker avvises.
# 11. Konfigfil lastes bare hvis den eies av root og ikke er gruppe-/
#     verdensskrivbar.
# 12. 802-1x.private-key-password "" fjernet fra kommandolinjen.
#
# ROBUSTHET
# 13. set -u + pipefail, umask 077, fast PATH, nullglob.
# 14. flock hindrer to samtidige kjøringer.
# 15. Rollback går nå LIFO, har backup i root-only katalog (ikke .backup-
#     rollback ved siden av originalen), og dekker FILE_CREATED og
#     SERVICE_STATE.
# 16. Netplan-endring lager faktisk backup — 3.5.9 registrerte rollback-
#     punkt uten å ta kopi, så tilbakerulling gjorde ingenting.
# 17. PEM-splitting med awk i stedet for csplit (csplit lager tomme
#     ledd-filer og oppfører seg ulikt på ulike plattformer).
# 18. Profiler oppdateres idempotent i stedet for slett-og-opprett, så en
#     fungerende tilkobling ikke rives ned unødig.
# 19. Eksakt SSID-match (grep -Fxq) i stedet for grep -qw.
# 20. NM-navn med kolon håndteres (nm_unescape).
# 21. Pakkeinstallasjon sjekker exit-kode i stedet for &>/dev/null.
# 22. OS-deteksjon i subshell — /etc/os-release forurenser ikke lenger
#     skriptets variabler.
# 23. Verifisering sjekker nå at nøkkel og sertifikat hører sammen, at
#     kjeden validerer mot CA-fila, og at nøkkelrettighetene er 0600.
# 24. Nettverkstest mot NDES-verten i stedet for ping 8.8.8.8.
# 25. --test skriver ikke lenger til /var/log og krever ikke root.
# 26. Eksponentiell backoff på getcert resubmit.
# 27. semanage+restorecon der tilgjengelig, ellers chcon (chcon alene
#     overlever ikke relabel).
# 28. Argumentparsing med --help/--version/--verbose/--no-rollback/
#     --update-pins og feil på ukjente argumenter.
# 29. Konfigurasjon kan flyttes ut i /etc/enterprise-network-deploy.conf.
#
# MIGRERING FRA 3.5.9
#  - Første kjøring lagrer CA-pins og skriver dem i loggen. Verifiser dem
#    mot PKI-ansvarlig før du ruller ut bredt.
#  - Kjørte du 3.5.9 tidligere, står systemet trolig med global crypto
#    policy DEFAULT:SHA1. Sjekk: update-crypto-policies --show
#    Tilbakestill med: update-crypto-policies --set DEFAULT
#  - Sett RADIUS_DOMAIN_SUFFIX til NPS-serverens domenesuffiks. Feiler
#    autentisering etter oppgradering, er dette første sted å se.
#
# ═════════════════════════════════════════════════════════════════════════════
# 4.0.0 -> 4.1.0  — integrert setup-forticlient-trust-p12.sh
# ═════════════════════════════════════════════════════════════════════════════
#
# Nytt stadium [8C/9], slått av som standard (VPN_BUNDLE=true eller
# --vpn-bundle). Kjører uavhengig av om FortiClient er installert.
#
# RETTET FRA ORIGINALEN
#  A. Trust anchor ble hentet over http:// og installert direkte. En MITM
#     kunne plante et vilkårlig rot-CA på maskinen. Nå: https som standard,
#     valgfri fingerprint-pin, og — viktigst — sertifikatet MÅ validere mot
#     systemets eksisterende trust store. Da kan et innsatt selvsignert CA
#     ikke passere uansett transport.
#  B. Fast standardpassord "Test1234" på PKCS#12-fila, som også ble skrevet
#     til stdout. Nå genereres 128 bit tilfeldig passord som lagres i
#     ${CERT_BASE_PATH}/p12-password (0600, root). Passordet skrives aldri
#     til loggfila.
#  C. -passout "pass:..." på kommandolinjen var synlig i ps for alle
#     brukere. Nå -passout file:.
#  D. CN-parsingen (sed 's/.*CN=\([^,]*\).*/\1/p') matcher ikke OpenSSL 3,
#     som skriver "CN = Navn" med mellomrom. På Fedora 38+ falt derfor ALLE
#     sertifikater tilbake til navnet "indra-ca" og overskrev hverandre —
#     bare det siste havnet i trust store. Per-sertifikat-installasjonen er
#     fjernet; CA-kjeden installeres én gang i stadium [6/9].
#  E. openssl rsa -traditional feiler stille på EC-nøkler og falt tilbake
#     til å kopiere en potensielt kryptert nøkkel. Nå openssl pkey.
#  F. Ingen kontroll av at nøkkel og sertifikat hørte sammen. Nå
#     sammenlignes public key-hashene før pakking, og .p12-fila leses
#     tilbake for å bekrefte at den er gyldig.
#  G. .p12 ble skrevet med default umask før chmod 600 — kort vindu der
#     privatnøkkelen lå lesbar. Nå bygges alt under umask 077.
#  H. awk-splittingen skrev også en indra-0.pem av alt før første
#     BEGIN CERTIFICATE og lukket aldri filhåndtak.
#
# BEHOLDT
#  - PKCS#12 bygges i kompatibilitetsmodus (3DES/SHA1) som standard, siden
#    FortiClient ikke alltid leser OpenSSL 3 sine AES-256/PBKDF2-defaults.
#    P12_COMPAT=false gir moderne format.
#  - Faller tilbake til ${CERT_BASE_PATH}/ når det ikke finnes en innlogget
#    ikke-root-bruker (imaging, headless).
#
# MERK
#  - Legges .p12 i en brukers hjemmekatalog, kan den brukeren autentisere
#    som maskinen. Skriptet advarer om dette. Vurder P12_TARGET_USER="" for
#    å beholde fila systemvidt.
#
# ═════════════════════════════════════════════════════════════════════════════
# 4.1.0 -> 4.2.0
# ═════════════════════════════════════════════════════════════════════════════
#
#  I. RETTET: rollback-punktet for p12-passordfila ble registrert ETTER at
#     fila var opprettet, så betingelsen var alltid usann og fila ble aldri
#     ryddet ved tilbakerulling. (Innført i 4.1.0.)
#
#  J. Fornyelseshook. certmonger bytter ut machine.crt/machine.key ved
#     fornyelse. NetworkManager leser filene på nytt, men en PKCS#12 som
#     allerede er importert i FortiClient blir stående med gammel nøkkel og
#     slutter å virke — typisk 8-12 måneder etter utrulling, når ingen
#     lenger husker hva som ble gjort. Skriptet installerer seg selv på
#     ${INSTALL_PATH} og kobler på "getcert request -C", som bygger pakka
#     på nytt automatisk.
#
#  K. --vpn-bundle-only: kjører kun trust anchors + .p12. Dette er det
#     kollegaens skript egentlig gjorde, og det er hooken sitt inngangspunkt.
#     Kan kjøres når som helst etter at enrollment er ferdig.
#
#  L. --status: leser og rapporterer tilstand uten å endre noe.
#     Sertifikatets utløp, certmonger-status, om hooken er koblet på,
#     CA-pins, profilenes server-match, kryptopolicy og .p12-plassering.
#     Ment for feilsøking uten å risikere å gjøre vondt verre.
#
#  M. .p12 bygges bare om når sertifikatet faktisk er endret (fingerprint
#     lagres i .p12-cert-fingerprint). --force-p12 overstyrer. Uten dette
#     ville hver kjøring generert nytt passord og ugyldiggjort en allerede
#     importert pakke.
#
#  N. P12_TARGET_USER er nå tom som standard = systemsti. Maskinens
#     privatnøkkel havner ikke i en brukers hjemmekatalog med mindre det er
#     eksplisitt bedt om ("auto" for sudo-brukeren, eller et brukernavn).
#
#  O. logrotate-konfig installeres, så deploymentloggen ikke vokser fritt.
#
# ═════════════════════════════════════════════════════════════════════════════
# 4.2.0 -> 4.3.0
# ═════════════════════════════════════════════════════════════════════════════
#
#  P. Nytt stadium [8D/9]: FortiClient-RPM. Verifiserer SHA-256 og GPG-
#     signatur før installasjon, sjekker at pakka faktisk er den forventede
#     versjonen, håndterer nedgradering eksplisitt (dnf downgrade ->
#     rpm -Uvh --oldpackage -> remove+install), verifiserer versjonen ETTER
#     installasjon, og setter versjonslås så en dnf update ikke løfter den
#     tilbake. Nedgradering krever FORTICLIENT_ALLOW_DOWNGRADE=true.
#
#  Q. EMS-registrering via "forticlient epctrl register <kode>". Det er
#     denne koden brukeren ellers må taste inn manuelt. Koden skrives aldri
#     til loggfila. Hopper over hvis endepunktet allerede er registrert, og
#     håndterer at EMS svarer med en SAML-URL.
#
#  R. En fingerprint-pin er nå et gyldig alternativ til kjedevalidering for
#     ekstra trust anchors. Nødvendig når rot-CA-en er fjernet fra distroens
#     trust store — f.eks. DigiCert Global Root CA (G1), som fjernes fra
#     trust stores i løpet av 2026. Uten pin avvises anchoren fortsatt, og
#     feilmeldingen viser fingerprinten som ble hentet, klar til innliming.
#
#  S. --forticlient-only for å kjøre kun FortiClient-delen.
#     --status viser nå versjon, EMS-tilkobling og om versjonslåsen er aktiv.
#
# ═════════════════════════════════════════════════════════════════════════════
# 4.3.0 -> 4.4.0
# ═════════════════════════════════════════════════════════════════════════════
#
#  T. P12_PASSWORD_MODE=fixed er tilbake. Et fast passord i konfigfila er en
#     ren transportkode for én engangsimport. Da er filas LEVETID et større
#     spørsmål enn passordets styrke. Advarer én gang under 12 tegn og
#     fortsetter.
#
#  U. P12_RETENTION_DAYS (standard 14). Etter import er .p12 bare en kopi av
#     maskinens privatnøkkel som blir liggende i en hjemmekatalog — med et
#     passord som er likt på hele flåten. En systemd-timer rydder den bort.
#     0 = behold for alltid.
#
#  V. "Levert"-markør: når fila er ryddet bort bygges den ikke opp igjen ved
#     neste kjøring så lenge sertifikatet er uendret. Uten dette ville hver
#     kjøring lagt nøkkelen ut på nytt og gjort oppryddingen meningsløs.
#     --force-p12 lager den likevel (ny maskin, ny bruker, ny import).
#
#  W. --cleanup-p12 er timerens inngangspunkt. --status viser om pakka er
#     levert og ryddet, og hvilken frist som gjelder.
#
# OM FAST PASSORD
#  Ett lekket .p12 gir maskinens 802.1X- OG VPN-identitet, og med fast
#  passord gjelder samme kode for hele flåten. Kontrollene som faktisk betyr
#  noe blir derfor: rettigheter 0600, at katalogen ikke synkroniseres eller
#  backes opp (OneDrive, Nextcloud, hjemmekatalog-backup), og at fila ryddes
#  bort etter import.
#
# ═════════════════════════════════════════════════════════════════════════════
# 4.4.0 -> 4.5.0
# ═════════════════════════════════════════════════════════════════════════════
#
#  X. RETTET (årsaken til CA_UNREACHABLE på Fedora 41+):
#     GetCACert er usignert og lykkes selv når SHA-1 er blokkert. Det er
#     PKCSReq — selve sertifikatforespørselen — som er SHA-1-signert.
#     I 4.0-4.4 var auto-eskaleringen bare koblet på CA-nedlastingen, altså
#     det ene steget som ALLTID lykkes. Den ble derfor aldri utløst der den
#     trengtes, og enrollment døde med CA_UNREACHABLE.
#     Nå eskaleres SHA-1 også fra ventesløyfen, ved CA_UNREACHABLE,
#     CA_UNCONFIGURED og NEED_SCEP_ENCRYPTION_CERT, med resubmit og nytt
#     forsøk i stedet for å avbryte.
#
#  Y. CA_UNREACHABLE prøver i tillegg på nytt to ganger med pause. Azure App
#     Proxy foran NDES er ikke alltid umiddelbart tilgjengelig.
#
#  Z. diagnose_scep_failure() kjøres ved enhver enrollment-feil: viser
#     forespørsel, CA-config, kryptopolicy, om drop-in faktisk har effekt,
#     certmonger-journal — og sjekker om SKALLET har proxy mens
#     CERTMONGER-TJENESTEN ikke har det, som gir nøyaktig samme
#     CA_UNREACHABLE og er lett å bomme på.
#
# AA. .p12 legges nå som standard på brukerens skrivebord
#     (P12_TARGET_USER=auto, P12_TARGET_SUBDIR=DESKTOP). Katalogen slås opp
#     med xdg-user-dir kjørt SOM brukeren, så lokaliserte navn (Skrivebord,
#     Skrivbord) treffer; ellers fallback til hjemmekatalogen.
#     FortiClient tar sin egen kopi ved import, så fila er ren transport og
#     ryddes bort etter P12_RETENTION_DAYS som før.
#
# AB. Sluttmeldingen skriver ut full sti og kode, så den som setter opp
#     maskinen slipper å lete.
#
# ═════════════════════════════════════════════════════════════════════════════
# 4.5.0 -> 4.6.0
# ═════════════════════════════════════════════════════════════════════════════
#
# AC. P12_IMPORT_NSS (standard false): importerer .p12 i brukerens
#     NSS-database (~/.pki/nssdb) i tillegg til kopien på skrivebordet.
#     Det er brukersertifikatlageret Chromium, Evolution m.fl. bruker på
#     Linux. Kjøres SOM brukeren via runuser, hopper over hvis
#     sertifikatet allerede er der, og sender passordet via fil framfor
#     argument.
#
#     MERK: Fortinet dokumenterer ingen CLI-import for FortiClient på Linux
#     — dokumentasjonssiden "Installing certificates on the client" dekker
#     kun Windows og macOS. Dette er derfor et kvalifisert forsøk, ikke en
#     verifisert metode, og er avslått som standard.
#
#     Slik finner dere den faktiske plasseringen på en maskin der importen
#     virker:
#       touch /tmp/fc-marker
#       <importer i FortiClient-GUI>
#       sudo find "$HOME" /etc/forticlient /opt/forticlient \
#            /var/lib/forticlient -newer /tmp/fc-marker -type f 2>/dev/null
#     Da kan filene legges rett på plass i stedet.
#
# ═════════════════════════════════════════════════════════════════════════════
# 4.6.0 -> 4.7.0
# ═════════════════════════════════════════════════════════════════════════════
#
# AD. Brukerutvelgelsen for .p12 var for naiv: kun SUDO_USER med logname som
#     reserve. Kjørt som ren root over SSH, eller under imaging der
#     sluttbrukeren ikke finnes ennå, havnet fila systemvidt uten at det var
#     tydelig hvorfor. Ny rekkefølge:
#       1. eksplisitt brukernavn i konfig
#       2. SUDO_USER
#       3. logname
#       4. aktiv grafisk sesjon (loginctl) — dekker root-over-SSH
#       5. eneste vanlige bruker (UID >= 1000 med hjemmekatalog)
#       6. systemsti + advarsel som sier hvorfor og hva man gjør
#
# AE. Begrunnelsen for valget logges ("kjørte sudo", "eneste vanlige bruker"
#     osv.), og sluttmeldingen viser hvem som eier fila.
#
# AF. Verifiseringen feiler nå hvis .p12 ligger i en hjemmekatalog men eies
#     av root med 0600 — da kan brukeren ikke åpne den, og feilen ville
#     ellers først dukket opp hos sluttbrukeren.
#
# AG. Et ugyldig brukernavn i P12_TARGET_USER gir nå en tydelig feilmelding
#     i stedet for stille fallback.
#
# ═════════════════════════════════════════════════════════════════════════════
# 4.7.2 -> 4.8.0
# ═════════════════════════════════════════════════════════════════════════════
#
# AH. Kjedereparasjon via AIA. FIX_CHAIN_HOSTS / --fix-chain <vert[:port]>.
#
#     Problemet: gatewayen sender bare sitt eget sertifikat i handshaken,
#     ikke mellom-CA-ene over. Windows skjuler dette ved å hente de
#     manglende leddene via AIA-feltet (Authority Information Access ->
#     CA Issuers). OpenSSL gjør det ikke. Derfor virker samme gateway på
#     Windows og feiler på Linux med
#     "unable to get local issuer certificate".
#
#     Skriptet gjør nå det Windows gjør: leser sertifikatet fra gatewayen,
#     følger AIA opptil fem ledd, og installerer de manglende mellom-CA-ene
#     lokalt. Til slutt valideres sertifikatet UTEN hjelpeargumenter, kun
#     mot trust store, som bevis på at det faktisk virker.
#
#     Integritet: hvert hentede sertifikat må validere mot trust store før
#     det installeres, og må ha CA:TRUE. Derfor er http:// akseptert her —
#     AIA-URLer er http per RFC 5280, og en angriper kan ikke bytte inn noe
#     som validerer mot en rot systemet allerede stoler på.
#
#     Dette er en lokal reparasjon per maskin. Den varige fiksen er å
#     importere mellom-CA-et på gatewayen, så alle klienter får full kjede.
#
# ═════════════════════════════════════════════════════════════════════════════
# 4.8.0 -> 4.9.0
# ═════════════════════════════════════════════════════════════════════════════
#
# AI. Indra-standarder bakt inn, så skriptet virker uten konfigfil:
#       VPN_BUNDLE=true, P12_PASSWORD_MODE=fixed, P12_PASSWORD=Test1234,
#       P12_TARGET_USER=auto (skrivebordet), FORTICLIENT_ALLOW_DOWNGRADE=true.
#
# AJ. RapidSSL-mellom-CA-et er nå standard trust anchor. Det er dette som
#     mangler når FortiClient sier
#       ca_validate_cert: /CN=*.indra.no unable to get local issuer certificate
#     FortiGaten sender det ikke i handshaken, og OpenSSL henter det ikke
#     selv slik Windows gjør.
#
# AK. http:// aksepteres for trust anchors NÅR EXTRA_ANCHOR_REQUIRE_CHAIN=true.
#     Integriteten ligger i at sertifikatet må ha CA:TRUE og validere mot
#     systemets eksisterende trust store — et innsatt sertifikat blir avvist
#     uansett transport. AIA-URLer er http per RFC 5280, og den offisielle
#     adressen til dette mellom-CA-et finnes ikke over https.
#
# AL. FIX_CHAIN_HOSTS står fortsatt tom: den krever gatewayens vertsnavn, som
#     skriptet ikke kan gjette. Trengs den, kjør
#       --fix-chain <vert:port>
#     Anchoren over løser uansett det konkrete problemet uten vertsnavn.
#
# ═════════════════════════════════════════════════════════════════════════════
# 4.9.0 -> 4.9.1
# ═════════════════════════════════════════════════════════════════════════════
#
# AM. Når .p12 beholdes uendret, sier loggen nå hvilken fil det gjelder, når
#     den ble laget og hvilket sertifikat den inneholder. "hopper over" så
#     ut som om skriptet ikke gjorde jobben sin.
#
# AN. Verifiseringen sammenligner nå sertifikatet INNE i .p12 med
#     machine.crt. Er de ulike — f.eks. en pakke som ble liggende igjen fra
#     før en fornyelse — feiler verifiseringen med kommandoen for å bygge om,
#     i stedet for at brukeren oppdager det når VPN-en nekter å koble til.
#
# ═════════════════════════════════════════════════════════════════════════════
# 4.9.1 -> 4.10.0
# ═════════════════════════════════════════════════════════════════════════════
#
# AO. RETTET: idempotens-sjekken så bare på sertifikatets fingerprint. Endret
#     passordmodus (f.eks. random -> fixed da Test1234 ble bakt inn) uten at
#     sertifikatet ble fornyet, ble den gamle .p12-fila liggende — med et
#     passord brukeren ikke har fått utlevert. Import ville feilet med
#     "feil passord" uten at noe i loggen tydet på problemet.
#     Nå testes det at fila faktisk lar seg åpne med passordet som gjelder nå;
#     ellers bygges den om.
#
# AP. current_p12_password() skiller mellom "lag et nytt passord" og "hvilket
#     passord gjelder for fila som allerede finnes". I random-modus hentes
#     det lagrede fra P12_PASSWORD_FILE — et nytt kall til
#     generate_p12_password ville gitt en ny tilfeldig verdi og fått enhver
#     kontroll til å feile.
#
# AQ. Utdaterte kopier av .p12 andre steder i brukerens hjemmekatalog fjernes
#     når en ny bygges — typisk etter at plasseringen ble flyttet fra
#     hjemmekatalogen til skrivebordet. Ellers ligger det to filer der og
#     brukeren importerer den gale.
#
# ═════════════════════════════════════════════════════════════════════════════
# 4.10.0 -> 4.10.1
# ═════════════════════════════════════════════════════════════════════════════
#
# AR. P12_RETENTION_DAYS er endret fra 14 til 0 (behold).
#     FortiClient på Linux lagrer stien til .p12 sammen med passordet, ikke
#     bare innholdet. Automatisk sletting kunne derfor brutt VPN-en to uker
#     etter utrulling, samtidig på alle maskiner, med en årsak ingen ville
#     koblet til dette skriptet.
#     Oppryddingen finnes fortsatt og kan slås på når det er verifisert at
#     FortiClient tar sin egen kopi:
#         mv ~/Desktop/indra-machine.p12 /tmp/ && <koble til VPN>
#     Virker VPN fortsatt -> sett P12_RETENTION_DAYS=14.
#
# ═════════════════════════════════════════════════════════════════════════════
# 4.10.1 -> 4.11.0
# ═════════════════════════════════════════════════════════════════════════════
#
# AS. Bekreftet ved test: FortiClient lagrer STIEN til .p12 og leser fila ved
#     hver tilkobling. Flyttes den, feiler VPN-en. Fila må derfor bli
#     liggende, og plasseringen må være et sted ingen rydder bort.
#
#     P12_TARGET_SUBDIR er endret fra DESKTOP til "do-not-delete/p12cert".
#     Mappa opprettes 0700 og eies av brukeren, og får en LES-MEG.txt som
#     forklarer hvorfor den ikke skal slettes.
#
# AT. P12_TARGET_SUBDIR godtar nå vanlige relative stier, ikke bare
#     XDG-nøkkelord. Absolutte stier og ".." avvises — verdien kommer fra
#     konfig, men fila skrives som root inn i en brukers hjemmekatalog.
#
# AU. Opprydding av utdaterte kopier søker nå tre nivåer ned, så .p12-filer
#     fra tidligere plasseringer (skrivebordet) fjernes når den nye bygges.
#
# ═════════════════════════════════════════════════════════════════════════════
# 4.11.0 -> 4.12.0
# ═════════════════════════════════════════════════════════════════════════════
#
# AV. EXTRA_ANCHOR_MODE: chain-only | anchor | auto (standard auto).
#
#     chain-only legger mellom-CA-et i /etc/pki/ca-trust/source/ i stedet for
#     .../source/anchors/. update-ca-trust(8) beskriver forskjellen: filer
#     utenfor anchors/ blir "simply known to the system, which might be
#     helpful to assist cryptographic software in constructing chains of
#     certificates" — kjent for kjedebygging, men ikke et tillitsanker.
#     Tilliten kommer fortsatt fra rot-CA-en.
#
#     Haken: p11-kit gir nøytrale sertifikater tomme trust-flagg, og de havner
#     ikke nødvendigvis i den ekstraherte tls-ca-bundle.pem som OpenSSL-baserte
#     klienter (inkludert FortiClient) leser. Om det virker avhenger av
#     p11-kit-versjonen.
#
#     Derfor MÅLER skriptet resultatet i stedet for å anta:
#     cert_reaches_system_bundle() sjekker om sertifikatet faktisk dukker opp
#     i bundlen klientene leser. I auto eskaleres det til anchor hvis ikke.
#     I chain-only sies det tydelig fra at det ikke nådde fram.
#     --status viser hvilken av delene som gjelder på maskinen nå.
#
#     Debian/Ubuntu har ingen nøytral variant (update-ca-certificates stoler
#     alltid på det den finner), så der brukes anchor uansett.
#
# MERK OM TILLITSFLATEN
#  Å legge inn mellom-CA-et utvider ikke settet av sertifikater maskinen
#  godtar: DigiCert-roten som signerte det ligger allerede i trust store, så
#  alt det utsteder validerer fra før. Den ene reelle forskjellen er at et
#  tillitsanker overlever at rota fjernes — relevant nå som DigiCerts G1-rot
#  er under utfasing. chain-only beholder koblingen til rota; anchor bryter
#  den.
#
# ═════════════════════════════════════════════════════════════════════════════
# 4.12.0 -> 4.13.0
# ═════════════════════════════════════════════════════════════════════════════
#
# AW. GATEWAY_CERT / --gateway-cert <fil>: kjedereparasjon med utgangspunkt i
#     gatewayens sertifikatfil i stedet for en TLS-forbindelse. Godtar PEM,
#     DER og PKCS#7. Krever verken vertsnavn, åpen port eller at maskinen er
#     på nettet mot gatewayen.
#
#     Sertifikatet er samtidig et VERIFIKASJONSMÅL: etter at mellom-CA-et er
#     installert valideres det uten hjelpeargumenter. Validerer det, er
#     kjeden beviselig komplett — sterkere enn "mellom-CA-et ligger i
#     bundlen". Kopien lagres i GATEWAY_CERT_STORE, så senere kjøringer og
#     --status kan bruke den uten at fila oppgis på nytt.
#
# AX. check_gateway_cert_expiry(): varsler når gateway-sertifikatet nærmer
#     seg utløp (GATEWAY_CERT_WARN_DAYS, standard 45). Går det ut, feiler VPN
#     for hele flåten samtidig. Ved fornyelse kan utstederen endre seg — og
#     da må skriptet kjøres på nytt for å hente riktig mellom-CA.
#
# AY. fix_incomplete_chain og fix_chain_from_file deler nå
#     complete_chain_from_leaf(), så AIA-følging, installasjon og
#     sluttverifisering oppfører seg likt uansett hvor leaf-sertifikatet kom
#     fra.
#
# ═════════════════════════════════════════════════════════════════════════════
# 4.13.0 -> 4.13.1
# ═════════════════════════════════════════════════════════════════════════════
#
# AZ. EXTRA_ANCHOR_MODE er endret fra auto til anchor som standard.
#     Mellom-CA-et legges rett i /etc/pki/ca-trust/source/anchors/ — Linux sitt
#     "trusted certificate authorities"-lager. Det er den forutsigbare
#     varianten: sertifikatet havner alltid i bundlen klientene leser, uten
#     et måle- og eskaleringssteg som bare gir logglarm.
#     chain-only og auto står igjen for den som vil ha den snevrere varianten.
#
# BA. Anchor-plasseringen verifiseres nå også: etter update-ca-trust sjekkes
#     det at sertifikatet faktisk dukket opp i CA-bundlen. Feiler
#     update-ca-trust stille, sies det fra i stedet for at det oppdages når
#     VPN ikke virker.
#
# MERK: DET ER UTSTEDEREN SOM SKAL INN, IKKE SERVERSERTIFIKATET
#  Mellom-CA-et (RapidSSL TLS RSA CA G1) dekker alle sertifikater den
#  utsteder — også det som kommer ved fornyelse. Legger man i stedet
#  *.indra.no selv i CA-lageret, virker det til 12. desember 2026 og slutter
#  så å virke på hele flåten samtidig. Derfor installerer skriptet utstederen,
#  og bruker serversertifikatet kun som verifikasjonsmål.
#
# ═════════════════════════════════════════════════════════════════════════════
# 4.13.1 -> 4.14.0
# ═════════════════════════════════════════════════════════════════════════════
#
# BB. Skriptet installerer IKKE lenger RapidSSL-mellom-CA-et automatisk.
#     EXTRA_TRUST_ANCHORS er tom som standard: mellom-CA-et er lagt manuelt i
#     systemets klarerte CA-lager, og skal forvaltes der — ikke av to parter.
#
# BC. verify_vpn_chain(): ren kontroll, installerer og sletter ingenting.
#       - Med gateway-sertifikat (GATEWAY_CERT / --gateway-cert, eller lagret
#         i GATEWAY_CERT_STORE): validerer selve sertifikatet mot trust store.
#         Brutt kjede -> feilmelding med utsteder og AIA-URL til det som mangler.
#       - Uten: sjekker at VPN_CHAIN_EXPECT_ISSUER finnes i trust store
#         (~80 ms for hele bundlen). Tom verdi = hopp over.
#     Stopper ikke utrullingen — .p12 bygges uansett.
#
# BD. Rester fra 4.9-4.13 (RapidSSLTLSRSACAG1.pem, RapidSSL_TLS_RSA_CA_G1.pem)
#     rapporteres, med kommandoen for å fjerne dem. Skriptet sletter dem
#     ikke selv: er den manuelle kopien borte, er det skriptets kopi som
#     holder VPN i live, og den avgjørelsen er deres.
#
# BE. --status viser om forventet utsteder finnes i trust store, eventuelle
#     rester, og at skriptet ikke forvalter mellom-CA-et.
#
# UENDRET: .p12 bygges fortsatt for brukeren som kjører sudo, i
# $HOME/do-not-delete/p12cert/, med Test1234.
#
# ═════════════════════════════════════════════════════════════════════════════
# 4.14.0 -> 4.15.0
# ═════════════════════════════════════════════════════════════════════════════
#
# BF. RapidSSL TLS RSA CA G1 installeres igjen som standard. Den manuelle
#     varianten virket ikke på testmaskinen: trust list viste ingen RapidSSL,
#     og FortiClient-loggen viste
#       ca_validate_cert: /CN=fedora.ad.indra.no ok            <- klient OK
#       ca_validate_cert: /CN=*.indra.no unable to get local issuer certificate
#     Framgangsmåten er nøyaktig den som ble gjort for hånd: hent via AIA,
#     DER->PEM, kontroller mot eksisterende trust store, anchors/,
#     update-ca-trust extract. Opt-out: EXTRA_TRUST_ANCHORS=() i konfigfila.
#
# BG. Installasjonen bekreftes med p11-kit (p11_trust_state = "trust list"):
#     logger "trust: anchor", eller advarer hvis status er noe annet.
#
# BH. list_misplaced_leaf_anchors(): finner serversertifikater (CA:FALSE,
#     ikke selvsignert) i anchors/. Et serversertifikat som "anker" hjelper
#     ikke OpenSSL — det krever en kjede til en rot. Sannsynlig årsak til at
#     det manuelle forsøket ikke virket: *.indra.no lagt i trusted CA i
#     stedet for utstederen. Rapporteres med kommando for å fjerne dem,
#     slettes ikke automatisk.
#
# BI. Rester fra 4.9-4.13 rapporteres bare når skriptet ikke selv forvalter
#     mellom-CA-et — ellers er fila skriptets egen, ikke en rest.
#
# ═════════════════════════════════════════════════════════════════════════════
# 4.15.0 -> 4.16.0
# ═════════════════════════════════════════════════════════════════════════════
#
# BJ. RETTET: .p12 havnet hos teknikeren i stedet for sluttbrukeren.
#     Logg fra sal sin maskin: "Valgte bruker: user (har aktiv innlogget
#     sesjon)". Skriptet ble ikke startet med sudo fra sal, så det falt ned
#     til "første innloggede sesjon" — teknikerens konto. Og selv med sudo
#     ville teknikerens konto blitt valgt: skriptet antok at sluttbrukeren
#     kjører det selv.
#     Nå:
#       --user <navn>      sluttbrukeren angis eksplisitt (vinner over conf)
#       husket valg        lagres i P12_TARGET_USER_FILE; fornyelseshooken
#                          (uten terminal) og senere kjøringer treffer samme
#       flere mulige       interaktivt: spør, med skriptets gjetning som standard
#                          uten terminal: legg systemvidt + si fra, ALDRI gjett
#                          stille mellom to personer
#       aktiv skjermbruker erstatter "første sesjon i lista"
#       AD/SSSD-brukere    finnes via eierne av /home/* (UID > 65534 kommer
#                          ikke med i getent passwd uten enumerering)
#
# BK. .p12 som skriptet la hos ANDRE brukere enn sluttbrukeren fjernes når
#     den nye er på plass (kun skriptets egen sti, + LES-MEG.txt). Det er
#     maskinens privatnøkkel og skal ikke bli liggende hos teknikeren.
#
# BL. RETTET: falsk "finner ikke RapidSSL TLS RSA CA G1" på Fedora 44, rett
#     etter "verifisert: sertifikatet er nå i systemets CA-bundle".
#       - trust_store_has_cn: crl2pkcs7 er alt-eller-ingenting — ett
#         ulesbart sertifikat i bundlen gir null treff (påvist). Faller nå
#         tilbake til ett sertifikat om gangen med fast navneformat.
#       - trust list slås opp på sertifikatets ID (pkcs11:id = Subject Key
#         Identifier, påvist) i stedet for navnet.
#       - cert_cn bruker -nameopt RFC2253: uavhengig av "CN = x" (OpenSSL
#         3.0) vs "CN=x" (3.5 / Fedora 44).
#     Er sertifikatet i bundlen men trust list ikke finner det, logges det
#     som informasjon — bundlen er det klientene leser.
#
# BM. Ligger forventet mellom-CA i anchors/ men ikke i bundlen, sier
#     kontrollen nå nettopp det: kjør update-ca-trust extract.
#
# BN. "Profil ikke opprettet: IndraNavia" var falsk alarm på maskiner uten
#     WiFi-maskinvare. Nå bare informasjon der.
#
# BO. update-ca-trust kjøres med umask 022 (skriptet bruker 077). p11-kit
#     setter selv 0444 på filene (påvist), så dette er en ren sikring.
#
# ═════════════════════════════════════════════════════════════════════════════
# 4.16.0 -> 4.17.0
# ═════════════════════════════════════════════════════════════════════════════
#
# BP. --exclude-user <navn> / P12_EXCLUDE_USERS: kontoer som aldri er
#     sluttbruker. For utrulling via ManageEngine o.l.: agenten kjører som
#     root uten terminal, så skriptet kan ikke spørre. På maskiner med både
#     lokal adminkonto fra imaget og sluttbruker ville .p12 da havnet
#     systemvidt. Med adminkontoen utelatt blir sluttbrukeren eneste
#     kandidat, velges og huskes — uten at ME må kjenne brukernavnet per
#     maskin. Gjelder også husket valg og gjetning; --user vinner over lista.
#
# ═════════════════════════════════════════════════════════════════════════════
# 4.17.0 -> 4.18.0
# ═════════════════════════════════════════════════════════════════════════════
#
# BQ. Helautomatisk valg av sluttbruker — skriptet kjøres fra ManageEngine
#     UTEN argumenter, og .p12 havner hos den som bruker maskinen, uansett
#     hva personen heter:
#       - "user" (lokal adminkonto fra imaget) er utelatt som standard
#       - nøyaktig én domenebruker (AD/SSSD, står ikke i /etc/passwd)
#         -> den velges
#       - ellers: nøyaktig én kandidat som sitter ved skjermen -> den velges
#       - ellers (delt maskin, flere AD-brukere, ingen ved skjermen):
#         spør fra terminal, eller systemvidt + advarsel uten terminal
#     Valget huskes, så fornyelseshooken treffer samme person.
#     P12_EXCLUDE_USERS="" slår av standard-utelatelsen.
#
# 4.18.0 -> 4.18.1
# BR. Hjemmekataloger ett nivå dypere (/home/<domene>/<bruker>, SSSD
#     fallback_homedir=/home/%d/%u) finnes nå også når brukeren ikke er pålogget.

#!/usr/bin/env bash

# PlainID PAA Upgrade Script
# Version: 1.4.0

set -euo pipefail

# ============================================================================
# Configuration
# ============================================================================
COLOR_RESET=$'\e[0m'
COLOR_BRAND=$'\e[38;2;52;182;201m'
COLOR_INFO="$COLOR_BRAND"
COLOR_WARN=$'\e[1;33m'
COLOR_ERROR=$'\e[1;31m'
COLOR_SUCCESS=$'\e[1;32m'

DRY_RUN="${DRY_RUN:-false}"
DISK_BUFFER_MB="${DISK_BUFFER_MB:-512}"

# ============================================================================
# Logging
# ============================================================================
LOG_FILE=""

log_print() {
  local level="$1"; shift
  local message="$*"
  local color="$COLOR_INFO"
  local stream=1
  
  case "$level" in
    ERROR) color="$COLOR_ERROR"; stream=2 ;;
    WARN) color="$COLOR_WARN" ;;
    SUCCESS) color="$COLOR_SUCCESS" ;;
    INFO|*) color="$COLOR_INFO" ;;
  esac
  
  local ts line
  ts="$(date +%F' '%T)"
  line="[$ts] [$level] $message"
  
  if [[ "$stream" -eq 2 ]]; then
    printf '%b%s%b\n' "$color" "$line" "$COLOR_RESET" >&2
  else
    printf '%b%s%b\n' "$color" "$line" "$COLOR_RESET"
  fi
  
  [[ -n "$LOG_FILE" ]] && echo "$line" >> "$LOG_FILE"
}

log_info() { log_print INFO "$@"; }
log_warn() { log_print WARN "$@"; }
log_error() { log_print ERROR "$@"; }
log_success() { log_print SUCCESS "$@"; }
die() { log_error "$*"; exit 1; }

print_logo() {
  printf '%b' "${COLOR_BRAND}"
  cat <<'EOF'
                                           ////.                                
                 *////////////.            ///////////                          
               //////////////////          ///////////////                      
              ////////////////////               ////////////                   
             //////////////////////                   //////////                
             //////////////////////        ///           /////////              
             .////////////////////         ////////         ///////             
               //////////////////          ///////////       ///////            
                 //////////////            /////////////       //////.          
                                           ///////////////      //////          
                                           ////////////////      //////         
        //////////////////////////////     ////////////////      //////         
        //////////////////////////////     /////////////////     */////         
        //////                  //////     /////////////////     */////         
        //////                  //////     ////////////////,     //////         
         /////                  //////     ////////////////      //////         
          ////.                 //////     ///////////////      //////          
          /////                 //////     /////////////*      //////           
            ////                //////     ////////////       //////            
             ////               //////     /////////        //////              
               ///              //////     /////          ///////               
                 ///            //////                 ///////,                 
                    //          //////            //////////                    
                       /        ////////////////////////                        
                                ///////////////////                             
EOF
  printf '%b\n\n' "${COLOR_BRAND}PAA UPGRADE SCRIPT${COLOR_RESET}"
}

# ============================================================================
# Pure Bash Alias File Parser
# ============================================================================

extract_name() {
  local line="$1" type="$2" name
  case "$type" in
    export)
      name="${line#export }"
      name="${name%%=*}"
      name="${name// /}"
      ;;
    alias)
      name="${line#alias }"
      name="${name%%=*}"
      name="${name// /}"
      ;;
    function)
      name="${line#function }"
      name="${name%%(*}"
      name="${name// /}"
      ;;
  esac
  echo "$name"
}

parse_aliases_file() {
  local file="$1"
  
  # Parse exports
  awk '/^[[:space:]]*export[[:space:]]+[A-Za-z_][A-Za-z0-9_]*=/ {
    line = $0
    sub(/^[[:space:]]*export[[:space:]]+/, "", line)
    name = line
    sub(/=.*/, "", name)
    printf "export\t%s\t%s\n", name, $0
  }' "$file"
  
  # Parse aliases
  awk '/^[[:space:]]*alias[[:space:]]+[A-Za-z_][A-Za-z0-9_-]*=/ {
    line = $0
    sub(/^[[:space:]]*alias[[:space:]]+/, "", line)
    name = line
    sub(/=.*/, "", name)
    printf "alias\t%s\t%s\n", name, $0
  }' "$file"
  
  # Parse functions using awk with proper brace counting
  awk '
    /^[[:space:]]*(function[[:space:]]+)?[a-zA-Z0-9_]+[[:space:]]*(\(\))?[[:space:]]*\{/ {
      func_name = gensub(/^[[:space:]]*(function[[:space:]]+)?([a-zA-Z0-9_]+)[[:space:]]*(\(\))?[[:space:]]*\{.*/, "\\\\2", "1", $0)
      in_func = 1
      brace_level = gsub(/\{/, "{", $0) - gsub(/\}/, "}", $0)
      func_body = $0
      if (brace_level == 0) {
        # Single line function
        printf "function\t%s\t%s\n", func_name, func_body
        in_func = 0
        func_body = ""
      }
      next
    }
    
    in_func {
      brace_level += gsub(/\{/, "{", $0) - gsub(/\}/, "}", $0)
      func_body = func_body "\n" $0
      if (brace_level == 0) {
        printf "function\t%s\t%s\n", func_name, func_body
        in_func = 0
        func_body = ""
      }
    }
  ' "$file"
}

merge_aliases_files() {
  local old_file="$1" new_file="$2" output="$3"
  
  log_info "Merging alias files..."
  
  local old_data new_data
  old_data=$(parse_aliases_file "$old_file")
  new_data=$(parse_aliases_file "$new_file")
  
  declare -A old_exports old_aliases old_functions
  declare -A new_exports new_aliases new_functions
  declare -a new_order=()
  
  while IFS=$'\t' read -r type name content; do
    case "$type" in
      export) old_exports["$name"]="$content" ;;
      alias) old_aliases["$name"]="$content" ;;
      function) old_functions["$name"]="$content" ;;
    esac
  done <<< "$old_data"
  
  while IFS=$'\t' read -r type name content; do
    new_order+=("$type:$name")
    case "$type" in
      export) new_exports["$name"]="$content" ;;
      alias) new_aliases["$name"]="$content" ;;
      function) new_functions["$name"]="$content" ;;
    esac
  done <<< "$new_data"
  
  declare -a preserved_items=()
  
  {
    echo "# PID Directories"
    
    for item in "${new_order[@]}"; do
      local type="${item%%:*}" name="${item#*:}"
      
      if [[ "$type" == "export" ]]; then
        case "$name" in
          PAA_PACKAGE_VERSION|PLAINID_HOME)
            echo "${new_exports[$name]}"
            ;;
          JAVA_HOME|PATH|REDIS_*|WARP_PORT|APP_VDB_LAZY_INVALIDATE|AGENT_AWAITING_DURATION|CLIENT_SECRET_KEY|TENANT_ID|PAA_ID|REMOTE_WARP)
            if [[ -n "${old_exports[$name]:-}" ]]; then
              echo "${old_exports[$name]}"
              [[ "${old_exports[$name]}" != "${new_exports[$name]:-}" ]] && preserved_items+=("export:$name")
            elif [[ -n "${new_exports[$name]:-}" ]]; then
              echo "${new_exports[$name]}"
            fi
            ;;
          *)
            if [[ -n "${old_exports[$name]:-}" ]]; then
              echo "${old_exports[$name]}"
              [[ "${old_exports[$name]}" != "${new_exports[$name]}" ]] && preserved_items+=("export:$name")
            else
              echo "${new_exports[$name]}"
            fi
            ;;
        esac
        unset old_exports["$name"]
      fi
    done
    
    if [[ ${#old_exports[@]} -gt 0 ]]; then
      echo ""
      echo "# Custom exports preserved from previous version"
      for name in "${!old_exports[@]}"; do
        echo "${old_exports[$name]}"
        preserved_items+=("export:$name")
      done
    fi
    
    echo ""
    echo "# Health check"
    
    for item in "${new_order[@]}"; do
      local type="${item%%:*}" name="${item#*:}"
      
      case "$type" in
        alias)
          if [[ -n "${old_aliases[$name]:-}" ]]; then
            echo "${old_aliases[$name]}"
            [[ "${old_aliases[$name]}" != "${new_aliases[$name]}" ]] && preserved_items+=("alias:$name")
          else
            echo "${new_aliases[$name]}"
          fi
          unset old_aliases["$name"]
          ;;
        function)
          if [[ -n "${old_functions[$name]:-}" ]]; then
            echo ""
            echo "${old_functions[$name]}"
            [[ "${old_functions[$name]}" != "${new_functions[$name]}" ]] && preserved_items+=("function:$name")
          else
            echo ""
            echo "${new_functions[$name]}"
          fi
          unset old_functions["$name"]
          ;;
      esac
    done
    
    if [[ ${#old_aliases[@]} -gt 0 || ${#old_functions[@]} -gt 0 ]]; then
      echo ""
      echo "# Custom aliases/functions preserved from previous version"
      
      for name in "${!old_aliases[@]}"; do
        echo "${old_aliases[$name]}"
        preserved_items+=("alias:$name")
      done
      
      for name in "${!old_functions[@]}"; do
        echo ""
        echo "${old_functions[$name]}"
        preserved_items+=("function:$name")
      done
    fi
    
    echo ""
  } > "$output"
  
  if [[ ${#preserved_items[@]} -gt 0 ]]; then
    log_info "Preserved ${#preserved_items[@]} customizations from installed version:"
    for item in "${preserved_items[@]}"; do
      log_info "  - ${item}"
    done
  else
    log_info "No customizations detected - using cleanpack as-is"
  fi
}

# ============================================================================
# Disk Space Validation
# ============================================================================

check_disk_space() {
  log_info "=== Checking disk space ==="
  
  local tmp_base="${TMPDIR:-/tmp}"
  if [[ ! -d "$tmp_base" ]]; then
    log_warn "TMPDIR ($tmp_base) unavailable, falling back to /tmp"
    tmp_base="/tmp"
  fi
  
  log_info "Calculating directory sizes..."
  
  local install_size_mb source_size_mb home_free_mb
  install_size_mb=$(du -sm "$PLAINID_HOME" 2>/dev/null | awk '{print $1}')
  source_size_mb=$(du -sm "$SOURCE_DIR" 2>/dev/null | awk '{print $1}')
  home_free_mb=$(df -Pm "$PLAINID_HOME" 2>/dev/null | awk 'NR==2 {print $4}')
  
  install_size_mb="${install_size_mb:-0}"
  source_size_mb="${source_size_mb:-0}"
  
  log_info "Current installation size: ${install_size_mb} MB"
  log_info "Cleanpack size: ${source_size_mb} MB"
  
  local backup_required_mb
  backup_required_mb=$((install_size_mb + DISK_BUFFER_MB))
  
  log_info "Required space for backup: ${backup_required_mb} MB (installation + ${DISK_BUFFER_MB} MB buffer)"
  
  if [[ -n "$home_free_mb" ]]; then
    log_info "Free space on ${PLAINID_HOME}: ${home_free_mb} MB"
    if ((home_free_mb >= backup_required_mb)); then
      log_success "Disk space check: OK (${home_free_mb} MB >= ${backup_required_mb} MB)"
    else
      die "Insufficient disk space on ${PLAINID_HOME}: ${home_free_mb} MB available, need ${backup_required_mb} MB"
    fi
  else
    log_warn "Unable to determine free space on ${PLAINID_HOME}"
  fi
  
  log_info ""
}

# ============================================================================
# Service Management
# ============================================================================

trim_ws() {
  local s="$*"
  while [[ "$s" =~ ^[[:space:]] ]]; do
    s="${s#?}"
  done
  while [[ "$s" =~ [[:space:]]$ ]]; do
    s="${s%?}"
  done
  printf '%s' "$s"
}

services_need_stop() {
  local output="$1"
  local line status
  while IFS= read -r line; do
    [[ -z "$line" || "$line" != *:* ]] && continue
    status="${line#*:}"
    status="$(trim_ws "$status")"
    [[ -z "$status" ]] && continue
    case "$status" in
      DOWN|STOPPED|STOP|NOT\ RUNNING|INACTIVE|DISABLED)
        continue
        ;;
      *)
        return 0
        ;;
    esac
  done <<< "$output"
  return 1
}

ensure_services_stopped() {
  log_info "=== Checking PlainID services status ==="
  
  if [[ ! -r "$PLAINID_HOME/init/aliases" ]]; then
    log_warn "Cannot read ${PLAINID_HOME}/init/aliases"
    log_warn "Skipping service stop check"
    log_info ""
    return
  fi
  
  log_info "Sourcing aliases from: ${PLAINID_HOME}/init/aliases"
  set +u
  shopt -s expand_aliases
  # shellcheck disable=SC1090
  source "$PLAINID_HOME/init/aliases"
  set -u

  if ! type pid_status >/dev/null 2>&1; then
    log_warn "pid_status command not available"
    log_warn "Skipping service stop enforcement"
    log_info ""
    return
  fi

  log_info "Running pid_status check..."
  local pid_output
  pid_output="$(pid_status 2>&1 || true)"
  
  if [[ -n "$pid_output" ]]; then
    log_info "Current service status:"
    while IFS= read -r line; do
      [[ -z "$line" ]] && continue
      log_info "  $line"
    done <<< "$pid_output"
  fi

  if services_need_stop "$pid_output"; then
    log_warn "Detected running PlainID services!"
    
    if [[ "$DRY_RUN" == "true" ]]; then
      log_info "[DRY RUN] Would execute: stop_plainid_paa"
      log_info ""
      return
    fi
    
    log_info "Initiating service shutdown: stop_plainid_paa"
    
    bash -c "shopt -s expand_aliases; source '$PLAINID_HOME/init/aliases'; stop_plainid_paa" 2>&1 | grep -v "Terminated" || true
    
    log_info "Waiting for services to stop (up to 60 seconds)..."
    sleep 10
    
    local attempt
    for attempt in {1..12}; do
      pid_output="$(pid_status 2>&1 || true)"
      if [[ -n "$pid_output" ]]; then
        log_info "Status check #${attempt}/12:"
        while IFS= read -r line; do
          [[ -z "$line" ]] && continue
          log_info "  $line"
        done <<< "$pid_output"
      fi
      if ! services_need_stop "$pid_output"; then
        log_success "All services stopped successfully"
        log_info ""
        return
      fi
      sleep 5
    done
    die "Services still running after 60 seconds. Please stop manually."
  else
    log_success "All services are already stopped"
    log_info ""
  fi
}

# ============================================================================
# Rollback Functionality
# ============================================================================

rollback_from_backup() {
  local backup_tar="$1"
  
  if [[ ! -f "$backup_tar" ]]; then
    die "Backup archive not found: $backup_tar"
  fi
  
  log_warn "=== ROLLBACK MODE ==="
  log_warn "This will restore from: $backup_tar"
  
  if [[ "$DRY_RUN" == "true" ]]; then
    log_info "[DRY RUN] Would restore: $backup_tar -> $PLAINID_HOME"
    return 0
  fi
  
  if [[ -t 0 ]]; then
    local response
    read -r -p "Continue with rollback? [y/N]: " response
    response="${response:-N}"
    [[ ! "$response" =~ ^[Yy]$ ]] && die "Rollback cancelled by user"
  fi
  
  log_info "Extracting backup to temporary location..."
  local tmp_restore
  tmp_restore="$(mktemp -d -t plainid-rollback-XXXXXX)"
  
  if ! tar -xzf "$backup_tar" -C "$tmp_restore"; then
    rm -rf "$tmp_restore"
    die "Failed to extract backup archive"
  fi
  
  local backup_content
  backup_content=$(find "$tmp_restore" -mindepth 1 -maxdepth 1 -type d -print -quit)
  
  if [[ -z "$backup_content" ]]; then
    backup_content="$tmp_restore"
  fi
  
  if [[ ! -d "$backup_content" ]]; then
    rm -rf "$tmp_restore"
    die "Backup archive structure invalid"
  fi
  
  if [[ ! -f "$backup_content/init/aliases" ]]; then
    rm -rf "$tmp_restore"
    die "Backup does not contain init/aliases - not a valid PlainID backup"
  fi
  
  log_info "Restoring to $PLAINID_HOME..."
  
  local plainid_real
  plainid_real="$(cd "$PLAINID_HOME" && pwd -P)"
  
  rm -rf "${plainid_real:?}"/*
  cp -a "$backup_content/." "$plainid_real/"
  rm -rf "$tmp_restore"
  
  log_success "Rollback completed successfully"
  log_info "Please run: source ${PLAINID_HOME}/init/aliases"
}

# ============================================================================
# Source Directory Detection
# ============================================================================

detect_source_dir() {
  local script_dir="$1"
  
  if [[ -f "$script_dir/init/aliases" ]]; then
    echo "$script_dir"
    return 0
  fi
  
  if [[ -f "$script_dir/../init/aliases" ]]; then
    cd "$script_dir/.." && pwd
    return 0
  fi
  
  return 1
}

# ============================================================================
# Usage and Version
# ============================================================================

show_usage() {
  cat <<EOF
PlainID PAA Upgrade Script v1.3.0

Usage: $0 [OPTIONS]

Options:
  --dry-run                Run in dry-run mode (no changes applied)
  --source-dir=PATH        Specify cleanpack source directory
  --rollback=FILE          Rollback from backup archive
  -h, --help               Show this help message
  -v, --version            Show version information

Environment Variables:
  PLAINID_HOME             Path to PlainID installation (required)
  
Examples:
  # Standard upgrade
  ./upgrade.sh
  
  # Dry run
  ./upgrade.sh --dry-run
  
  # Explicit source directory
  ./upgrade.sh --source-dir=/tmp/cleanpack
  
  # Rollback
  ./upgrade.sh --rollback=/opt/plainid/plainid-backup-20250127_143022.tar.gz

EOF
}

# ============================================================================
# Main Upgrade Logic
# ============================================================================

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"
PLAINID_HOME="${PLAINID_HOME:-}"
SOURCE_DIR="${SOURCE_DIR:-}"
BACKUP_TAR=""

main() {
  local rollback_file=""
  
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --dry-run)
        DRY_RUN=true
        shift
        ;;
      --source-dir=*)
        SOURCE_DIR="${1#*=}"
        shift
        ;;
      --rollback=*)
        rollback_file="${1#*=}"
        shift
        ;;
      --rollback)
        rollback_file="${2:-}"
        [[ -z "$rollback_file" ]] && die "Usage: $0 --rollback <backup.tar.gz>"
        shift 2
        ;;
      -h|--help)
        show_usage
        exit 0
        ;;
      -v|--version)
        echo "PlainID PAA Upgrade Script v1.4.0"
        exit 0
        ;;
      *)
        log_error "Unknown option: $1"
        show_usage
        exit 1
        ;;
    esac
  done
  
  print_logo
  
  LOG_FILE="$SCRIPT_DIR/upgrade_$(date +%Y%m%d_%H%M%S).log"
  if ! touch "$LOG_FILE" 2>/dev/null; then
    LOG_FILE=""
    log_warn "Cannot create log file; continuing without file logging"
  fi
  
  if [[ -n "$rollback_file" ]]; then
    rollback_from_backup "$rollback_file"
    exit 0
  fi
  
  if [[ -z "$PLAINID_HOME" ]]; then
    die "PLAINID_HOME is not set. Please set it: export PLAINID_HOME=/opt/plainid"
  fi
  
  if [[ ! -d "$PLAINID_HOME" ]]; then
    die "PLAINID_HOME directory does not exist: $PLAINID_HOME"
  fi
  
  if [[ ! -w "$PLAINID_HOME" ]]; then
    die "PLAINID_HOME is not writable: $PLAINID_HOME (check permissions)"
  fi
  
  if [[ ! -f "$PLAINID_HOME/init/aliases" ]]; then
    die "PLAINID_HOME does not contain init/aliases: $PLAINID_HOME (not a valid PlainID installation)"
  fi
  
  log_info "PLAINID_HOME validated: $PLAINID_HOME"
  log_info ""
  
  log_info "=== Validating script location ==="
  local plainid_home_real script_dir_real
  plainid_home_real="$(cd "$PLAINID_HOME" && pwd -P)"
  script_dir_real="$(cd "$SCRIPT_DIR" && pwd -P)"
  
  log_info "Script directory: $SCRIPT_DIR"
  log_info "Script real path: $script_dir_real"
  log_info "PLAINID_HOME real path: $plainid_home_real"
  
  if [[ "$script_dir_real" == "$plainid_home_real"* ]]; then
    log_error "╔════════════════════════════════════════════════════════════════════╗"
    log_error "║                         ⚠️  CRITICAL ERROR  ⚠️                        ║"
    log_error "╚════════════════════════════════════════════════════════════════════╝"
    log_error ""
    log_error "Cannot run upgrade script from PLAINID_HOME directory!"
    log_error ""
    log_error "Script location: $SCRIPT_DIR"
    log_error "PLAINID_HOME:    $PLAINID_HOME"
    log_error ""
    log_error "Running upgrade from PLAINID_HOME will destroy the installation!"
    log_error ""
    log_error "SOLUTION:"
    log_error "  1. Extract cleanpack to a different location:"
    log_error "     tar -xzf cleanpack.tar.gz -C /tmp/"
    log_error ""
    log_error "  2. Run upgrade from the extracted cleanpack:"
    log_error "     cd /tmp/cleanpack"
    log_error "     ./upgrade.sh"
    log_error ""
    die "Upgrade aborted to prevent data loss"
  fi
  
  log_success "Script location check: OK (not running from PLAINID_HOME)"
  log_info ""
  
  log_info "=== Detecting cleanpack source ==="
  if [[ -z "$SOURCE_DIR" ]]; then
    log_info "SOURCE_DIR not specified, attempting auto-detection..."
    if SOURCE_DIR=$(detect_source_dir "$SCRIPT_DIR"); then
      log_success "Auto-detected cleanpack: $SOURCE_DIR"
    else
      die "Cannot auto-detect cleanpack. Use --source-dir=PATH option"
    fi
  else
    log_info "Using specified SOURCE_DIR: $SOURCE_DIR"
  fi
  
  [[ -d "$SOURCE_DIR" ]] || die "SOURCE_DIR not found: $SOURCE_DIR"
  [[ -f "$SOURCE_DIR/init/aliases" ]] || die "Not a valid cleanpack: missing init/aliases"
  
  log_success "Cleanpack validation: OK"
  log_info ""
  
  log_info "=== Configuration Summary ==="
  log_info "PLAINID_HOME: $PLAINID_HOME"
  log_info "SOURCE_DIR: $SOURCE_DIR"
  log_info "DRY_RUN: $DRY_RUN"
  log_info ""
  
  if [[ "$DRY_RUN" == "true" ]]; then
    log_warn "╔════════════════════════════════════════════════════════════════════╗"
    log_warn "║                    DRY RUN MODE - No changes                       ║"
    log_warn "╚════════════════════════════════════════════════════════════════════╝"
    log_warn ""
  fi
  
  check_disk_space
  
  [[ -f "$SOURCE_DIR/init/aliases" ]] || die "Not a valid cleanpack: $SOURCE_DIR/init/aliases not found"
  
  ensure_services_stopped
  
  log_info "=== Creating backup ==="
  local timestamp
  timestamp=$(date +%Y%m%d_%H%M%S)
  local backup_name="plainid-backup-${timestamp}.tar.gz"
  local temp_backup="/tmp/${backup_name}"
  BACKUP_TAR="${PLAINID_HOME}/${backup_name}"
  
  if [[ "$DRY_RUN" != "true" ]]; then
    log_info "Backup file: $BACKUP_TAR"
    log_info "Resolving real paths for backup..."
    
    local plainid_real
    plainid_real="$(cd "$PLAINID_HOME" && pwd -P)"
    local parent_dir
    parent_dir="$(dirname "$plainid_real")"
    local dir_name
    dir_name="$(basename "$plainid_real")"
    
    log_info "Backing up: ${parent_dir}/${dir_name}"
    log_info "Excluding: logs/"
    log_info "Creating archive in /tmp..."
    
    set +e
    tar --exclude='logs' -czf "$temp_backup" -C "$parent_dir" "$dir_name"
    local tar_exit=$?
    set -e
    
    if [[ $tar_exit -gt 1 ]]; then
      rm -f "$temp_backup"
      die "Backup failed (tar exit code: $tar_exit)"
    fi
    
    if [[ $tar_exit -eq 1 ]]; then
      log_warn "Some files changed during backup (this is normal)"
    fi
    
    log_info "Moving backup to final location..."
    mv "$temp_backup" "$BACKUP_TAR"
    
    local backup_size=""
    if [[ -f "$BACKUP_TAR" ]]; then
      backup_size=$(stat -c "%s" "$BACKUP_TAR" 2>/dev/null || stat -f "%z" "$BACKUP_TAR" 2>/dev/null || echo "")
    fi
    
    if [[ -n "$backup_size" && "$backup_size" =~ ^[0-9]+$ && "$backup_size" -gt 0 ]]; then
      local size_display
      if ((backup_size > 1073741824)); then
        size_display="$((backup_size / 1073741824))G"
      elif ((backup_size > 1048576)); then
        size_display="$((backup_size / 1048576))M"
      elif ((backup_size > 1024)); then
        size_display="$((backup_size / 1024))K"
      else
        size_display="${backup_size}B"
      fi
      log_success "Backup created: $BACKUP_TAR (${size_display})"
    else
      log_success "Backup created: $BACKUP_TAR"
    fi
  else
    log_info "[DRY RUN] Would create: $BACKUP_TAR"
  fi
  log_info ""
  
  log_info "=== Merging configuration files ==="
  local merged_aliases="/tmp/aliases.merged.$$"
  merge_aliases_files "$PLAINID_HOME/init/aliases" "$SOURCE_DIR/init/aliases" "$merged_aliases"
  
  if [[ "$DRY_RUN" == "true" ]]; then
    log_info "[DRY RUN] Merged aliases preview (first 30 lines):"
    head -30 "$merged_aliases" | while read -r line; do log_info "  $line"; done
    log_info "  ..."
    rm -f "$merged_aliases"
  else
    log_info "Installing merged aliases to: ${PLAINID_HOME}/init/aliases"
    cp "$merged_aliases" "$PLAINID_HOME/init/aliases"
    rm -f "$merged_aliases"
    log_success "Aliases merged and installed"
  fi
  log_info ""
  
  log_success "╔════════════════════════════════════════════════════════════════════╗"
  log_success "║              Upgrade completed successfully!                       ║"
  log_success "╚════════════════════════════════════════════════════════════════════╝"
  log_info ""
  log_info "Next steps:"
  log_info "  1. Rollback command (if needed):"
  log_info "     $0 --rollback=$BACKUP_TAR"
  log_info ""
  log_info "  2. Apply new configuration:"
  log_info "     source ${PLAINID_HOME}/init/aliases"
  log_info ""
  log_info "  3. Start services:"
  log_info "     start_plainid_paa"
  log_info ""
}

main "$@"

#!/usr/bin/env bash

# PlainID PAA Upgrade Script
# Version: 1.5.7

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

# Global statistics for merge operations
declare -g -A MERGE_STATS=(
  [functions_customized]=0
  [functions_new]=0
  [exports_preserved]=0
  [aliases_preserved]=0
  [exports_new]=0
  [aliases_new]=0
)

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
  printf '%b\n\n' "${COLOR_BRAND}PAA UPGRADE SCRIPT v1.5.7${COLOR_RESET}"
}

# ============================================================================
# Helper Functions
# ============================================================================

# Safely replace a function block in a file
replace_function_with_sed() {
  local output_file="$1" func_name="$2" func_content="$3"

  log_info "Replacing function '$func_name' in '$output_file'..."

  # Check if function exists first
  if ! grep -qE "(function[[:space:]]+)?${func_name}[[:space:]]*\(\)[[:space:]]*\{" "$output_file"; then
    log_warn "Function '$func_name' not found in output file - skipping"
    return 1
  fi

  # Use awk for line-by-line processing
  local temp_file temp_new_func
  temp_file=$(mktemp)
  temp_new_func=$(mktemp)
  
  # Write the new function content
  printf '%s' "$func_content" > "$temp_new_func"
  
  # Process file with awk
  awk -v func_name="$func_name" -v new_func_file="$temp_new_func" '
  BEGIN {
    in_target_func = 0
    brace_count = 0
    replaced = 0
  }
  
  # Match function start
  /^[[:space:]]*(function[[:space:]]+)?[a-zA-Z0-9_]+[[:space:]]*\(\)[[:space:]]*\{/ {
    # Extract function name from this line
    line_copy = $0
    gsub(/^[[:space:]]*(function[[:space:]]+)?/, "", line_copy)
    gsub(/[[:space:]]*\(\)[[:space:]]*\{.*/, "", line_copy)
    current_func = line_copy
    
    if (current_func == func_name && !replaced) {
      # This is our target function - replace it
      in_target_func = 1
      replaced = 1
      brace_count = gsub(/\{/, "{") - gsub(/\}/, "}")
      
      # Output the new function content
      while ((getline new_line < new_func_file) > 0) {
        print new_line
      }
      close(new_func_file)
      
      # If function ends on same line, we are done
      if (brace_count == 0) {
        in_target_func = 0
      }
      next
    }
  }
  
  # If inside target function, skip lines until closing brace
  in_target_func {
    brace_count += gsub(/\{/, "{") - gsub(/\}/, "}")
    if (brace_count == 0) {
      in_target_func = 0
    }
    next
  }
  
  # Output all other lines
  { print }
  ' "$output_file" > "$temp_file"
  
  # Check if replacement happened
  if ! diff -q "$output_file" "$temp_file" >/dev/null 2>&1; then
    mv "$temp_file" "$output_file"
    rm -f "$temp_new_func"
    log_success "Function '$func_name' replaced successfully"
    return 0
  else
    log_warn "Function '$func_name' - no changes detected"
    rm -f "$temp_file" "$temp_new_func"
    return 1
  fi
}

# ============================================================================
# Pure Bash Alias File Parser (Portable)
# ============================================================================

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

  # Parse functions using portable awk (no gensub)
  awk '
    /^[[:space:]]*(function[[:space:]]+)?[a-zA-Z0-9_]+[[:space:]]*\(\)[[:space:]]*\{/ {
      # Extract function name portably
      func_line = $0
      sub(/^[[:space:]]*(function[[:space:]]+)?/, "", func_line)
      sub(/[[:space:]]*\(\)[[:space:]]*\{.*/, "", func_line)
      func_name = func_line
      
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

# ============================================================================
# Enhanced Configuration Merge
# ============================================================================

merge_aliases_files() {
  local old_file="$1" new_file="$2" output="$3"

  log_info "Merging alias files..."
  log_info "  Old (installed): $old_file"
  log_info "  New (cleanpack): $new_file"
  log_info "  Output: $output"

  # Start with the new file as base
  cp "$new_file" "$output"

  # Parse both files
  local old_data new_data
  old_data=$(parse_aliases_file "$old_file")
  new_data=$(parse_aliases_file "$new_file")

  # Build associative arrays
  declare -A new_items old_functions old_exports old_aliases

  # Track what exists in new file
  while IFS=$'\t' read -r type name content; do
    [[ -z "$type" ]] && continue
    new_items["${type}:${name}"]=1
    case "$type" in
      export) ((MERGE_STATS[exports_new]++)) || true ;;
      alias) ((MERGE_STATS[aliases_new]++)) || true ;;
      function) ((MERGE_STATS[functions_new]++)) || true ;;
    esac
  done <<< "$new_data"

  # Find items from old file
  while IFS=$'\t' read -r type name content; do
    [[ -z "$type" ]] && continue
    
    case "$type" in
      function)
        if [[ -n "${new_items["function:${name}"]:-}" ]]; then
          # Function exists in both - this is a customization
          old_functions["$name"]="$content"
          log_info "  → Detected customized function: $name"
        else
          # Function only in old file - preserve it
          log_info "  → Preserving custom function: $name"
          echo "" >> "$output"
          echo "$content" >> "$output"
        fi
        ;;
      export)
        if [[ -z "${new_items["export:${name}"]:-}" ]]; then
          # Export only in old file - preserve it
          old_exports["$name"]="$content"
          log_info "  → Preserving custom export: $name"
          ((MERGE_STATS[exports_preserved]++)) || true
        fi
        ;;
      alias)
        if [[ -z "${new_items["alias:${name}"]:-}" ]]; then
          # Alias only in old file - preserve it
          old_aliases["$name"]="$content"
          log_info "  → Preserving custom alias: $name"
          ((MERGE_STATS[aliases_preserved]++)) || true
        fi
        ;;
    esac
  done <<< "$old_data"

  # Append preserved custom exports
  if [[ ${#old_exports[@]} -gt 0 ]]; then
    {
      echo ""
      echo "# ============================================================================"
      echo "# Custom Exports (preserved from previous installation)"
      echo "# ============================================================================"
      for name in "${!old_exports[@]}"; do
        echo "${old_exports[$name]}"
      done
    } >> "$output"
  fi

  # Append preserved custom aliases
  if [[ ${#old_aliases[@]} -gt 0 ]]; then
    {
      echo ""
      echo "# ============================================================================"
      echo "# Custom Aliases (preserved from previous installation)"
      echo "# ============================================================================"
      for name in "${!old_aliases[@]}"; do
        echo "${old_aliases[$name]}"
      done
    } >> "$output"
  fi

  # Replace customized functions in the output
  for func_name in "${!old_functions[@]}"; do
    if replace_function_with_sed "$output" "$func_name" "${old_functions[$func_name]}"; then
      ((MERGE_STATS[functions_customized]++)) || true
    fi
  done

  log_success "Alias files merged successfully"
  
  # Display merge summary
  log_info ""
  log_info "=== Merge Summary ==="
  log_info "From new cleanpack:"
  log_info "  • Functions: ${MERGE_STATS[functions_new]}"
  log_info "  • Exports: ${MERGE_STATS[exports_new]}"
  log_info "  • Aliases: ${MERGE_STATS[aliases_new]}"
  log_info ""
  log_info "Preserved from old installation:"
  log_info "  • Customized functions: ${MERGE_STATS[functions_customized]}"
  log_info "  • Custom exports: ${MERGE_STATS[exports_preserved]}"
  log_info "  • Custom aliases: ${MERGE_STATS[aliases_preserved]}"
  log_info ""
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
# Cleanpack Validation
# ============================================================================

validate_cleanpack() {
  local source="$1"

  log_info "=== Validating cleanpack integrity ==="

  # Check for required files/directories
  local required_paths=(
    "init/aliases"
  )

  local missing=0
  for path in "${required_paths[@]}"; do
    if [[ ! -e "$source/$path" ]]; then
      log_error "  ✗ Missing required path: $path"
      ((missing++)) || true
    else
      log_info "  ✓ Found: $path"
    fi
  done

  if ((missing > 0)); then
    die "Cleanpack validation failed: $missing missing required path(s)"
  fi

  # Check if aliases file is readable and non-empty
  if [[ ! -r "$source/init/aliases" ]]; then
    die "Cleanpack aliases file is not readable: $source/init/aliases"
  fi

  if [[ ! -s "$source/init/aliases" ]]; then
    die "Cleanpack aliases file is empty: $source/init/aliases"
  fi

  # Try to parse aliases file
  local parse_test
  if ! parse_test=$(parse_aliases_file "$source/init/aliases" 2>&1); then
    log_error "Failed to parse cleanpack aliases file:"
    log_error "$parse_test"
    die "Cleanpack aliases file parsing failed"
  fi

  log_success "Cleanpack validation: OK"
  log_info ""
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
# Backup with Verification
# ============================================================================

create_backup() {
  local timestamp="$1"
  local backup_name="plainid-backup-${timestamp}.tar.gz"
  local temp_backup="/tmp/${backup_name}"
  local final_backup="${PLAINID_HOME}/${backup_name}"

  log_info "=== Creating backup ==="

  if [[ "$DRY_RUN" == "true" ]]; then
    log_info "[DRY RUN] Would create: $final_backup"
    echo "$final_backup"
    return 0
  fi

  log_info "Backup file: $final_backup"
  log_info "Resolving real paths for backup..."

  local plainid_real parent_dir dir_name
  plainid_real="$(cd "$PLAINID_HOME" && pwd -P)"
  parent_dir="$(dirname "$plainid_real")"
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

  # Verify backup integrity (basic check)
  log_info "Verifying backup archive integrity..."
  if ! tar -tzf "$temp_backup" >/dev/null 2>&1; then
    rm -f "$temp_backup"
    die "Backup verification failed - archive is corrupted"
  fi

  log_success "Backup created and verified"

  log_info "Moving backup to final location..."
  mv "$temp_backup" "$final_backup"

  local backup_size=""
  if [[ -f "$final_backup" ]]; then
    backup_size=$(stat -c "%s" "$final_backup" 2>/dev/null || stat -f "%z" "$final_backup" 2>/dev/null || echo "")
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
    log_success "Backup created: $final_backup (${size_display})"
  else
    log_success "Backup created: $final_backup"
  fi

  log_info ""
  echo "$final_backup"
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
PlainID PAA Upgrade Script v1.5.7

Usage: $0 [OPTIONS]

Options:
  --dry-run                Run in dry-run mode (no changes applied)
  --source-dir=PATH        Specify cleanpack source directory
  --rollback=FILE          Rollback from backup archive
  -h, --help               Show this help message
  -v, --version            Show version information

Environment Variables:
  PLAINID_HOME             Path to PlainID installation (required)
  DISK_BUFFER_MB           Disk space buffer in MB (default: 512)

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
        echo "PlainID PAA Upgrade Script v1.5.7"
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
  else
    log_info "Logging to: $LOG_FILE"
  fi
  log_info ""

  if [[ -n "$rollback_file" ]]; then
    rollback_from_backup "$rollback_file"
    exit 0
  fi

  # Validate PLAINID_HOME
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

  # Validate script location
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

  # Detect cleanpack source
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

  # Validate cleanpack
  validate_cleanpack "$SOURCE_DIR"

  # Configuration summary
  log_info "=== Configuration Summary ==="
  log_info "PLAINID_HOME: $PLAINID_HOME"
  log_info "SOURCE_DIR: $SOURCE_DIR"
  log_info "DRY_RUN: $DRY_RUN"
  log_info "DISK_BUFFER_MB: $DISK_BUFFER_MB"
  log_info ""

  if [[ "$DRY_RUN" == "true" ]]; then
    log_warn "╔════════════════════════════════════════════════════════════════════╗"
    log_warn "║                    DRY RUN MODE - No changes                       ║"
    log_warn "╚════════════════════════════════════════════════════════════════════╝"
    log_warn ""
  fi

  # Check disk space
  check_disk_space

  # Ensure services are stopped
  ensure_services_stopped

  # Create backup
  local timestamp
  timestamp=$(date +%Y%m%d_%H%M%S)
  BACKUP_TAR=$(create_backup "$timestamp")

  # Merge configuration files
  log_info "=== Merging configuration files ==="
  local merged_aliases="/tmp/aliases.merged.$$"
  merge_aliases_files "$PLAINID_HOME/init/aliases" "$SOURCE_DIR/init/aliases" "$merged_aliases"

  if [[ "$DRY_RUN" == "true" ]]; then
    log_info "[DRY RUN] Merged aliases preview (first 50 lines):"
    head -50 "$merged_aliases" | while read -r line; do log_info "  $line"; done
    log_info "  ..."
    log_info ""
    log_info "[DRY RUN] Would install to: ${PLAINID_HOME}/init/aliases"
    rm -f "$merged_aliases"
  else
    log_info "Installing merged aliases to: ${PLAINID_HOME}/init/aliases"
    cp "$merged_aliases" "$PLAINID_HOME/init/aliases"
    rm -f "$merged_aliases"
    log_success "Aliases merged and installed"
  fi
  log_info ""

  # Success summary
  log_success "╔════════════════════════════════════════════════════════════════════╗"
  log_success "║              Upgrade completed successfully!                       ║"
  log_success "╚════════════════════════════════════════════════════════════════════╝"
  log_info ""
  log_info "Next steps:"
  log_info ""
  log_info "  1. Rollback command (if needed):"
  log_info "     $0 --rollback=$BACKUP_TAR"
  log_info ""
  log_info "  2. Apply new configuration:"
  log_info "     source ${PLAINID_HOME}/init/aliases"
  log_info ""
  log_info "  3. Start services:"
  log_info "     start_plainid_paa"
  log_info ""
  
  if [[ -n "$LOG_FILE" ]]; then
    log_info "Full log available at: $LOG_FILE"
    log_info ""
  fi
}

main "$@"

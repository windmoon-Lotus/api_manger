"""Shared security result reason codes and quality classification helpers."""

REQUEST_EXCEPTION = "request_exception"
PAYLOAD_NOT_BUILT = "payload_not_built"
UNRESOLVED_PATH_PLACEHOLDER = "unresolved_path_placeholder"
VERIFY_PAYLOAD_NOT_BUILT = "verify_payload_not_built"
CREATED_RESOURCE_ID_NOT_FOUND = "created_resource_id_not_found"
ROUTE_NOT_FOUND = "route_not_found"
API_NOT_IMPLEMENTED = "api_not_implemented"
OWNER_NO_BUSINESS_DATA = "owner_no_business_data"
TOKEN_VERIFY_FAIL = "token_verify_fail"
SERVER_ERROR = "server_error"

ATTACKER_NOT_FOUND = "attacker_not_found"
ATTACKER_EMPTY_OR_ERROR = "attacker_empty_or_error"
ATTACKER_DELETE_STILL_EXISTS = "attacker_delete_2xx_but_owner_resource_still_exists"
ATTACKER_DELETE_REMOVED_VERIFIED = "attacker_delete_removed_owner_resource_verified_by_get"
ATTACKER_DELETE_WITHOUT_GET_VERIFICATION = "attacker_delete_2xx_without_get_verification"

BOTH_ACCOUNTS_CONSTRUCTED = "both_accounts_constructed_successfully"
ROUTE_NOT_FOUND_FOR_ALL_ACCOUNTS = "route_not_found_for_all_accounts"
INVALID_OR_MISSING_BUSINESS_PARAMETERS = "invalid_or_missing_business_parameters"
AUTH_OR_PERMISSION_DENIED_FOR_ALL_ACCOUNTS = "auth_or_permission_denied_for_all_accounts"
MIXED_STATUS_CODES = "mixed_status_codes"

FIXTURE_CREATE_DETAIL_UPDATE_DELETE_CONFIRMED = "create_detail_update_delete_confirmed"
FIXTURE_CREATE_LIST_UPDATE_DELETE_CONFIRMED = "create_list_update_delete_confirmed"
NEEDS_FIXTURE_BUILDER = "needs_fixture_builder"


EVALUABLE_EXACT = {
    ATTACKER_NOT_FOUND,
    ATTACKER_EMPTY_OR_ERROR,
    ATTACKER_DELETE_STILL_EXISTS,
    ATTACKER_DELETE_REMOVED_VERIFIED,
    BOTH_ACCOUNTS_CONSTRUCTED,
}

VERIFIED_EXACT = {
    ATTACKER_NOT_FOUND,
    ATTACKER_DELETE_STILL_EXISTS,
    ATTACKER_DELETE_REMOVED_VERIFIED,
}

EVALUABLE_PREFIXES = (
    "attacker_blocked_http_",
    "attacker_rejected_http_",
)

VERIFIED_PREFIXES = (
    "attacker_blocked_http_",
)

NOT_EVALUABLE_EXACT = {
    REQUEST_EXCEPTION,
    PAYLOAD_NOT_BUILT,
    UNRESOLVED_PATH_PLACEHOLDER,
    VERIFY_PAYLOAD_NOT_BUILT,
    CREATED_RESOURCE_ID_NOT_FOUND,
    ROUTE_NOT_FOUND,
    API_NOT_IMPLEMENTED,
    OWNER_NO_BUSINESS_DATA,
    TOKEN_VERIFY_FAIL,
    SERVER_ERROR,
    ROUTE_NOT_FOUND_FOR_ALL_ACCOUNTS,
    INVALID_OR_MISSING_BUSINESS_PARAMETERS,
    AUTH_OR_PERMISSION_DENIED_FOR_ALL_ACCOUNTS,
}

NOT_EVALUABLE_PREFIXES = (
    "owner_create_status_",
    "owner_write_status_",
    "owner_read_status_",
    "owner_detail_status_",
    "owner_list_status_",
    "created_resource_id_not_found",
    "route_not_found",
    "api_not_implemented",
    "token_verify_fail",
    "server_error",
)

NOT_EVALUABLE_CONTAINS = (
    "payload_not_built",
    "unresolved_path_placeholder",
    "verify_payload_not_built",
    "owner_no_business_data",
    "request_exception",
)


def attacker_blocked_http(status_code):
    return f"attacker_blocked_http_{status_code}"


def attacker_rejected_http(status_code):
    return f"attacker_rejected_http_{status_code}"


def owner_create_status(status_code):
    return f"owner_create_status_{status_code}"


def is_evaluable_reason(reason):
    reason = str(reason or "")
    return reason in EVALUABLE_EXACT or reason.startswith(EVALUABLE_PREFIXES)


def is_verified_reason(reason):
    reason = str(reason or "")
    return reason in VERIFIED_EXACT or reason.startswith(VERIFIED_PREFIXES)


def is_not_evaluable_reason(reason):
    reason = str(reason or "").lower()
    if reason in NOT_EVALUABLE_EXACT:
        return True
    if reason.startswith(NOT_EVALUABLE_PREFIXES):
        return True
    return any(marker in reason for marker in NOT_EVALUABLE_CONTAINS)


def all_known_reason_codes():
    return {
        *EVALUABLE_EXACT,
        *VERIFIED_EXACT,
        *NOT_EVALUABLE_EXACT,
        ATTACKER_DELETE_WITHOUT_GET_VERIFICATION,
        MIXED_STATUS_CODES,
        NEEDS_FIXTURE_BUILDER,
        FIXTURE_CREATE_DETAIL_UPDATE_DELETE_CONFIRMED,
        FIXTURE_CREATE_LIST_UPDATE_DELETE_CONFIRMED,
    }

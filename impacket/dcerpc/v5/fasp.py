# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright Fortra, LLC and its affiliated companies
#
# All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   [MS-FASP] Firewall and Advanced Security Protocol Interface implementation
#
#   Helper functions start with "h"<name of the call>.
#   No test cases have been addded thus far in the development cycle but once that does occur; it can be found in tests/dcerpc/test_fasp.py
#   Note that this protocol is exposed via a dyanmically assigned port so you will need to go through the EPM, as well as the fact that your DC may not expose the endpoint
#   so you may need to play around with the settings a little bit. Documentation for this protocol and others like it can be found in impacket.wiki :3

# Author: Abdul Mhanni

from impacket import system_errors
from impacket.dcerpc.v5.dtypes import BOOL, BOOLEAN, BYTE, DWORD, FILETIME, GUID, LONG64, LPDWORD, LPSTR, LPWSTR, NULL, PBOOL, PGUID, PULONG, PUSHORT, ULONG, ULONGLONG, USHORT, UUID, WCHAR, WORD
from impacket.dcerpc.v5.enum import Enum
from impacket.dcerpc.v5.ndr import NDRCALL, NDRENUM, NDRPOINTER, NDRSTRUCT, NDRUNION, NDRUniConformantArray
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.uuid import uuidtup_to_bin

MSRPC_UUID_FASP = uuidtup_to_bin(('6b5bdd1e-528c-422c-af8c-a4079be4fe48', '1.0'))

class DCERPCSessionError(DCERPCException):
    def __init__(self, error_string=None, error_code=None, packet=None):
        DCERPCException.__init__(self, error_string, error_code, packet)

    def __str__( self ):
        key = self.error_code
        if key in system_errors.ERROR_MESSAGES:
            error_msg_short = system_errors.ERROR_MESSAGES[key][0]
            error_msg_verbose = system_errors.ERROR_MESSAGES[key][1]
            return 'FASP SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        else:
            return 'FASP SessionError: unknown error code: 0x%x' % self.error_code

################################################################################
# CONSTANTS
################################################################################

FW_BINARY_VERSION_2_0 = 0x0200
FW_CURRENT_BINARY_VERSION = 0x0221
FW_CURRENT_SCHEMA_VERSION = 0x0221
FW_ICMP_CODE_ANY = 0x00000100
FW_IP_PROTOCOL_ANY = 0x00000100
FW_PROFILE_CONFIG_LOG_FILE_SIZE_MIN = 0x00000001
FW_PROFILE_CONFIG_LOG_FILE_SIZE_MAX = 0x00007FFF
FW_GLOBAL_CONFIG_CRL_CHECK_MAX = 0x00000002
FW_GLOBAL_CONFIG_SA_IDLE_TIME_MAX = 0x00000E10
FW_GLOBAL_CONFIG_SA_IDLE_TIME_MIN = 0x0000012C
FW_HYPERV_VM_CREATOR0_SCHEMA_VERSION = 0x0220
FW_HYPERV_PORT0_SCHEMA_VERSION = 0x0220
FW_HYPERV_PORT1_SCHEMA_VERSION = 0x0221
FW_HYPERV_RULE0_SCHEMA_VERSION = 0x0220
FW_HYPERV_RULE1_SCHEMA_VERSION = 0x0221

################################################################################
# ENUMERATIONS
################################################################################

class FW_STORE_TYPE(NDRENUM):
    class enumItems(Enum):
        FW_STORE_TYPE_INVALID                                                        = 0
        FW_STORE_TYPE_GP_RSOP                                                        = 1
        FW_STORE_TYPE_LOCAL                                                          = 2
        FW_STORE_TYPE_NOT_USED_VALUE_3                                               = 3
        FW_STORE_TYPE_NOT_USED_VALUE_4                                               = 4
        FW_STORE_TYPE_DYNAMIC                                                        = 5
        FW_STORE_TYPE_GPO                                                            = 6
        FW_STORE_TYPE_DEFAULTS                                                       = 7
        FW_STORE_TYPE_NOT_USED_VALUE_8                                               = 8
        FW_STORE_TYPE_NOT_USED_VALUE_9                                               = 9
        FW_STORE_TYPE_NOT_USED_VALUE_10                                              = 10
        FW_STORE_TYPE_NOT_USED_VALUE_11                                              = 11
        FW_STORE_TYPE_NOT_USED_VALUE_12                                              = 12
        FW_STORE_TYPE_MAX                                                            = 13

class FW_TRANSACTIONAL_STATE(NDRENUM):
    class enumItems(Enum):
        FW_TRANSACTIONAL_STATE_NONE                                                  = 0
        FW_TRANSACTIONAL_STATE_NO_FLUSH                                              = 1
        FW_TRANSACTIONAL_STATE_MAX                                                   = 2

class FW_PROFILE_TYPE(NDRENUM):
    class enumItems(Enum):
        FW_PROFILE_TYPE_INVALID                                                      = 0
        FW_PROFILE_TYPE_DOMAIN                                                       = 1
        FW_PROFILE_TYPE_STANDARD                                                     = 2
        FW_PROFILE_TYPE_PRIVATE                                                      = 2
        FW_PROFILE_TYPE_PUBLIC                                                       = 4
        FW_PROFILE_TYPE_ALL                                                          = 2147483647
        FW_PROFILE_TYPE_CURRENT                                                      = 2147483648
        FW_PROFILE_TYPE_NONE                                                         = 2147483649

class FW_POLICY_ACCESS_RIGHT(NDRENUM):
    class enumItems(Enum):
        FW_POLICY_ACCESS_RIGHT_INVALID                                               = 0
        FW_POLICY_ACCESS_RIGHT_READ                                                  = 1
        FW_POLICY_ACCESS_RIGHT_READ_WRITE                                            = 2
        FW_POLICY_ACCESS_RIGHT_MAX                                                   = 3

class FW_POLICY_STORE_FLAGS(NDRENUM):
    class enumItems(Enum):
        FW_POLICY_STORE_FLAGS_NONE                                                   = 0
        FW_POLICY_STORE_FLAGS_DELETE_DYNAMIC_RULES_AFTER_CLOSE                       = 1
        FW_POLICY_STORE_FLAGS_OPEN_GP_CACHE                                          = 2
        FW_POLICY_STORE_FLAGS_USE_GP_CACHE                                           = 4
        FW_POLICY_STORE_FLAGS_SAVE_GP_CACHE                                          = 8
        FW_POLICY_STORE_FLAGS_NOT_USED_VALUE_16                                      = 16
        FW_POLICY_STORE_FLAGS_MAX                                                    = 32

class FW_RULE_DUPLICATE_STATUS_FLAGS(NDRENUM):
    class enumItems(Enum):
        FW_DUPLICATE_STATUS_FLAGS_EVALUATING                                         = 1
        FW_DUPLICATE_STATUS_FLAGS_HAS_DUPLICATE                                      = 2
        FW_DUPLICATE_STATUS_FLAGS_IS_ENFORCED                                        = 4

class FW_PORT_KEYWORD(NDRENUM):
    class enumItems(Enum):
        FW_PORT_KEYWORD_NONE                                                         = 0
        FW_PORT_KEYWORD_DYNAMIC_RPC_PORTS                                            = 1
        FW_PORT_KEYWORD_RPC_EP                                                       = 2
        FW_PORT_KEYWORD_TEREDO_PORT                                                  = 4
        FW_PORT_KEYWORD_IP_TLS_IN                                                    = 8
        FW_PORT_KEYWORD_IP_TLS_OUT                                                   = 16
        FW_PORT_KEYWORD_DHCP                                                         = 32
        FW_PORT_KEYWORD_PLAYTO_DISCOVERY                                             = 64
        FW_PORT_KEYWORD_MDNS                                                         = 128
        FW_PORT_KEYWORD_CORTANA_OUT                                                  = 256
        FW_PORT_KEYWORD_PROXIMAL_TCP_CDP                                             = 512
        FW_PORT_KEYWORD_MAX                                                          = 1024
        FW_PORT_KEYWORD_MAX_V2_1                                                     = 8
        FW_PORT_KEYWORD_MAX_V2_10                                                    = 32
        FW_PORT_KEYWORD_MAX_V2_20                                                    = 128
        FW_PORT_KEYWORD_MAX_V2_24                                                    = 256
        FW_PORT_KEYWORD_MAX_V2_25                                                    = 512

class FW_DIRECTION(NDRENUM):
    class enumItems(Enum):
        FW_DIR_INVALID                                                               = 0
        FW_DIR_IN                                                                    = 1
        FW_DIR_OUT                                                                   = 2
        FW_DIR_MAX                                                                   = 3

class FW_INTERFACE_TYPE(NDRENUM):
    class enumItems(Enum):
        FW_INTERFACE_TYPE_ALL                                                        = 0
        FW_INTERFACE_TYPE_LAN                                                        = 1
        FW_INTERFACE_TYPE_WIRELESS                                                   = 2
        FW_INTERFACE_TYPE_REMOTE_ACCESS                                              = 4
        FW_INTERFACE_TYPE_MOBILE_BBAND                                               = 8
        FW_INTERFACE_TYPE_MAX                                                        = 16
        FW_INTERFACE_TYPE_MAX_V2_23                                                  = 8

class FW_ADDRESS_KEYWORD(NDRENUM):
    class enumItems(Enum):
        FW_ADDRESS_KEYWORD_NONE                                                      = 0
        FW_ADDRESS_KEYWORD_LOCAL_SUBNET                                              = 1
        FW_ADDRESS_KEYWORD_DNS                                                       = 2
        FW_ADDRESS_KEYWORD_DHCP                                                      = 4
        FW_ADDRESS_KEYWORD_WINS                                                      = 8
        FW_ADDRESS_KEYWORD_DEFAULT_GATEWAY                                           = 16
        FW_ADDRESS_KEYWORD_INTRANET                                                  = 32
        FW_ADDRESS_KEYWORD_INTERNET                                                  = 64
        FW_ADDRESS_KEYWORD_PLAYTO_RENDERERS                                          = 128
        FW_ADDRESS_KEYWORD_REMOTE_INTRANET                                           = 256
        FW_ADDRESS_KEYWORD_CAPTIVE_PORTAL                                            = 512
        FW_ADDRESS_KEYWORD_INTERNAL_LOCAL_ADDRESSES                                  = 1024
        FW_ADDRESS_KEYWORD_MAX_V2_10                                                 = 32
        FW_ADDRESS_KEYWORD_MAX_V2_29                                                 = 512
        FW_ADDRESS_KEYWORD_MAX_V2_33                                                 = 1024
        FW_ADDRESS_KEYWORD_MAX                                                       = 2048

class FW_DYNAMIC_KEYWORD_ADDRESS_FLAGS(NDRENUM):
    class enumItems(Enum):
        FW_DYNAMIC_KEYWORD_ADDRESS_FLAGS_NONE                                        = 0
        FW_DYNAMIC_KEYWORD_ADDRESS_FLAGS_AUTO_RESOLVE                                = 1
        FW_DYNAMIC_KEYWORD_ADDRESS_FLAGS_MAX                                         = 2

class FW_DYNAMIC_KEYWORD_ORIGIN_TYPE(NDRENUM):
    class enumItems(Enum):
        FW_DYNAMIC_KEYWORD_ORIGIN_INVALID                                            = 0
        FW_DYNAMIC_KEYWORD_ORIGIN_LOCAL                                              = 1
        FW_DYNAMIC_KEYWORD_ORIGIN_MDM                                                = 2
        FW_DYNAMIC_KEYWORD_ORIGIN_MAX                                                = 3

class FW_DYNAMIC_KEYWORD_ADDRESS_ENUM_FLAGS(NDRENUM):
    class enumItems(Enum):
        FW_DYNAMIC_KEYWORD_ADDRESS_ENUM_FLAGS_NONE                                   = 0
        FW_DYNAMIC_KEYWORD_ADDRESS_ENUM_FLAGS_AUTO_RESOLVE                           = 1
        FW_DYNAMIC_KEYWORD_ADDRESS_ENUM_FLAGS_NON_AUTO_RESOLVE                       = 2
        FW_DYNAMIC_KEYWORD_ADDRESS_ENUM_FLAGS_ALL                                    = 3
        FW_DYNAMIC_KEYWORD_ADDRESS_ENUM_FLAGS_MAX                                    = 4

class FW_TRUST_TUPLE_KEYWORD(NDRENUM):
    class enumItems(Enum):
        FW_TRUST_TUPLE_KEYWORD_NONE                                                  = 0
        FW_TRUST_TUPLE_KEYWORD_PROXIMITY                                             = 1
        FW_TRUST_TUPLE_KEYWORD_PROXIMITY_SHARING                                     = 2
        FW_TRUST_TUPLE_KEYWORD_WFD_PRINT                                             = 4
        FW_TRUST_TUPLE_KEYWORD_WFD_DISPLAY                                           = 8
        FW_TRUST_TUPLE_KEYWORD_WFD_DEVICES                                           = 16
        FW_TRUST_TUPLE_KEYWORD_WFD_KM_DRIVER                                         = 32
        FW_TRUST_TUPLE_KEYWORD_UPNP                                                  = 64
        FW_TRUST_TUPLE_KEYWORD_WFD_CDP                                               = 128
        FW_TRUST_TUPLE_KEYWORD_MAX                                                   = 256
        FW_TRUST_TUPLE_KEYWORD_MAX_V2_20                                             = 4
        FW_TRUST_TUPLE_KEYWORD_MAX_V2_26                                             = 32
        FW_TRUST_TUPLE_KEYWORD_MAX_V2_27                                             = 128

class FW_RULE_STATUS(NDRENUM):
    class enumItems(Enum):
        FW_RULE_STATUS_OK                                                            = 65536
        FW_RULE_STATUS_PARTIALLY_IGNORED                                             = 131072
        FW_RULE_STATUS_IGNORED                                                       = 262144
        FW_RULE_STATUS_PARSING_ERROR                                                 = 524288
        FW_RULE_STATUS_PARSING_ERROR_NAME                                            = 524289
        FW_RULE_STATUS_PARSING_ERROR_DESC                                            = 524290
        FW_RULE_STATUS_PARSING_ERROR_APP                                             = 524291
        FW_RULE_STATUS_PARSING_ERROR_SVC                                             = 524292
        FW_RULE_STATUS_PARSING_ERROR_RMA                                             = 524293
        FW_RULE_STATUS_PARSING_ERROR_RUA                                             = 524294
        FW_RULE_STATUS_PARSING_ERROR_EMBD                                            = 524295
        FW_RULE_STATUS_PARSING_ERROR_RULE_ID                                         = 524296
        FW_RULE_STATUS_PARSING_ERROR_PHASE1_AUTH                                     = 524297
        FW_RULE_STATUS_PARSING_ERROR_PHASE2_CRYPTO                                   = 524298
        FW_RULE_STATUS_PARSING_ERROR_PHASE2_AUTH                                     = 524299
        FW_RULE_STATUS_PARSING_ERROR_RESOLVE_APP                                     = 524300
        FW_RULE_STATUS_PARSING_ERROR_MAINMODE_ID                                     = 524301
        FW_RULE_STATUS_PARSING_ERROR_PHASE1_CRYPTO                                   = 524302
        FW_RULE_STATUS_PARSING_ERROR_REMOTE_ENDPOINTS                                = 524303
        FW_RULE_STATUS_PARSING_ERROR_REMOTE_ENDPOINT_FQDN                            = 524304
        FW_RULE_STATUS_PARSING_ERROR_KEY_MODULE                                      = 524305
        FW_RULE_STATUS_PARSING_ERROR_LUA                                             = 524306
        FW_RULE_STATUS_PARSING_ERROR_FWD_LIFETIME                                    = 524307
        FW_RULE_STATUS_PARSING_ERROR_TRANSPORT_MACHINE_AUTHZ_SDDL                    = 524308
        FW_RULE_STATUS_PARSING_ERROR_TRANSPORT_USER_AUTHZ_SDDL                       = 524309
        FW_RULE_STATUS_PARSING_ERROR_NETNAMES_STRING                                 = 524310
        FW_RULE_STATUS_PARSING_ERROR_SECURITY_REALM_ID_STRING                        = 524311
        FW_RULE_STATUS_PARSING_ERROR_FQBN_STRING                                     = 524312
        FW_RULE_STATUS_SEMANTIC_ERROR                                                = 1048576
        FW_RULE_STATUS_SEMANTIC_ERROR_RULE_ID                                        = 1048592
        FW_RULE_STATUS_SEMANTIC_ERROR_PORTS                                          = 1048608
        FW_RULE_STATUS_SEMANTIC_ERROR_PORT_KEYW                                      = 1048609
        FW_RULE_STATUS_SEMANTIC_ERROR_PORT_RANGE                                     = 1048610
        FW_RULE_STATUS_SEMANTIC_ERROR_PORTRANGE_RESTRICTION                          = 1048611
        FW_RULE_STATUS_SEMANTIC_ERROR_ADDR_V4_SUBNETS                                = 1048640
        FW_RULE_STATUS_SEMANTIC_ERROR_ADDR_V6_SUBNETS                                = 1048641
        FW_RULE_STATUS_SEMANTIC_ERROR_ADDR_V4_RANGES                                 = 1048642
        FW_RULE_STATUS_SEMANTIC_ERROR_ADDR_V6_RANGES                                 = 1048643
        FW_RULE_STATUS_SEMANTIC_ERROR_ADDR_RANGE                                     = 1048644
        FW_RULE_STATUS_SEMANTIC_ERROR_ADDR_MASK                                      = 1048645
        FW_RULE_STATUS_SEMANTIC_ERROR_ADDR_PREFIX                                    = 1048646
        FW_RULE_STATUS_SEMANTIC_ERROR_ADDR_KEYW                                      = 1048647
        FW_RULE_STATUS_SEMANTIC_ERROR_LADDR_PROP                                     = 1048648
        FW_RULE_STATUS_SEMANTIC_ERROR_RADDR_PROP                                     = 1048649
        FW_RULE_STATUS_SEMANTIC_ERROR_ADDR_V6                                        = 1048650
        FW_RULE_STATUS_SEMANTIC_ERROR_LADDR_INTF                                     = 1048651
        FW_RULE_STATUS_SEMANTIC_ERROR_ADDR_V4                                        = 1048652
        FW_RULE_STATUS_SEMANTIC_ERROR_TUNNEL_ENDPOINT_ADDR                           = 1048653
        FW_RULE_STATUS_SEMANTIC_ERROR_DTE_VER                                        = 1048654
        FW_RULE_STATUS_SEMANTIC_ERROR_DTE_MISMATCH_ADDR                              = 1048655
        FW_RULE_STATUS_SEMANTIC_ERROR_PROFILE                                        = 1048656
        FW_RULE_STATUS_SEMANTIC_ERROR_ICMP                                           = 1048672
        FW_RULE_STATUS_SEMANTIC_ERROR_ICMP_CODE                                      = 1048673
        FW_RULE_STATUS_SEMANTIC_ERROR_IF_ID                                          = 1048688
        FW_RULE_STATUS_SEMANTIC_ERROR_IF_TYPE                                        = 1048689
        FW_RULE_STATUS_SEMANTIC_ERROR_ACTION                                         = 1048704
        FW_RULE_STATUS_SEMANTIC_ERROR_ALLOW_BYPASS                                   = 1048705
        FW_RULE_STATUS_SEMANTIC_ERROR_DO_NOT_SECURE                                  = 1048706
        FW_RULE_STATUS_SEMANTIC_ERROR_ACTION_BLOCK_IS_ENCRYPTED_SECURE               = 1048707
        FW_RULE_STATUS_SEMANTIC_ERROR_INCOMPATIBLE_FLAG_OR_ACTION_WITH_SECURITY_REALM = 1048708
        FW_RULE_STATUS_SEMANTIC_ERROR_DIR                                            = 1048720
        FW_RULE_STATUS_SEMANTIC_ERROR_PROT                                           = 1048736
        FW_RULE_STATUS_SEMANTIC_ERROR_PROT_PROP                                      = 1048737
        FW_RULE_STATUS_SEMANTIC_ERROR_DEFER_EDGE_PROP                                = 1048738
        FW_RULE_STATUS_SEMANTIC_ERROR_ALLOW_BYPASS_OUTBOUND                          = 1048739
        FW_RULE_STATUS_SEMANTIC_ERROR_DEFER_USER_INVALID_RULE                        = 1048740
        FW_RULE_STATUS_SEMANTIC_ERROR_FLAGS                                          = 1048752
        FW_RULE_STATUS_SEMANTIC_ERROR_FLAGS_AUTO_AUTH                                = 1048753
        FW_RULE_STATUS_SEMANTIC_ERROR_FLAGS_AUTO_BLOCK                               = 1048754
        FW_RULE_STATUS_SEMANTIC_ERROR_FLAGS_AUTO_DYN_RPC                             = 1048755
        FW_RULE_STATUS_SEMANTIC_ERROR_FLAGS_AUTHENTICATE_ENCRYPT                     = 1048756
        FW_RULE_STATUS_SEMANTIC_ERROR_FLAGS_AUTH_WITH_ENC_NEGOTIATE_VER              = 1048757
        FW_RULE_STATUS_SEMANTIC_ERROR_FLAGS_AUTH_WITH_ENC_NEGOTIATE                  = 1048758
        FW_RULE_STATUS_SEMANTIC_ERROR_FLAGS_ESP_NO_ENCAP_VER                         = 1048759
        FW_RULE_STATUS_SEMANTIC_ERROR_FLAGS_ESP_NO_ENCAP                             = 1048760
        FW_RULE_STATUS_SEMANTIC_ERROR_FLAGS_TUNNEL_AUTH_MODES_VER                    = 1048761
        FW_RULE_STATUS_SEMANTIC_ERROR_FLAGS_TUNNEL_AUTH_MODES                        = 1048762
        FW_RULE_STATUS_SEMANTIC_ERROR_FLAGS_IP_HTTPS_VER                             = 1048763
        FW_RULE_STATUS_SEMANTIC_ERROR_FLAGS_IP_TLS_VER                               = 1048763
        FW_RULE_STATUS_SEMANTIC_ERROR_PORTRANGE_VER                                  = 1048764
        FW_RULE_STATUS_SEMANTIC_ERROR_FLAGS_ADDRS_TRAVERSE_DEFER_VER                 = 1048765
        FW_RULE_STATUS_SEMANTIC_ERROR_FLAGS_AUTH_WITH_ENC_NEGOTIATE_OUTBOUND         = 1048766
        FW_RULE_STATUS_SEMANTIC_ERROR_FLAGS_AUTHENTICATE_WITH_OUTBOUND_BYPASS_VER    = 1048767
        FW_RULE_STATUS_SEMANTIC_ERROR_REMOTE_AUTH_LIST                               = 1048768
        FW_RULE_STATUS_SEMANTIC_ERROR_REMOTE_USER_LIST                               = 1048769
        FW_RULE_STATUS_SEMANTIC_ERROR_LOCAL_USER_LIST                                = 1048770
        FW_RULE_STATUS_SEMANTIC_ERROR_LUA_VER                                        = 1048771
        FW_RULE_STATUS_SEMANTIC_ERROR_LOCAL_USER_OWNER                               = 1048772
        FW_RULE_STATUS_SEMANTIC_ERROR_LOCAL_USER_OWNER_VER                           = 1048773
        FW_RULE_STATUS_SEMANTIC_ERROR_LUA_CONDITIONAL_VER                            = 1048774
        FW_RULE_STATUS_SEMANTIC_ERROR_FLAGS_SYSTEMOS_GAMEOS                          = 1048775
        FW_RULE_STATUS_SEMANTIC_ERROR_FLAGS_CORTANA_VER                              = 1048776
        FW_RULE_STATUS_SEMANTIC_ERROR_FLAGS_REMOTENAME                               = 1048777
        FW_RULE_STATUS_SEMANTIC_ERROR_FLAGS_ALLOW_PROFILE_CROSSING_VER               = 1048784
        FW_RULE_STATUS_SEMANTIC_ERROR_FLAGS_LOCAL_ONLY_MAPPED_VER                    = 1048785
        FW_RULE_STATUS_SEMANTIC_ERROR_PLATFORM                                       = 1048800
        FW_RULE_STATUS_SEMANTIC_ERROR_PLATFORM_OP_VER                                = 1048801
        FW_RULE_STATUS_SEMANTIC_ERROR_PLATFORM_OP                                    = 1048802
        FW_RULE_STATUS_SEMANTIC_ERROR_DTE_NOANY_ADDR                                 = 1048816
        FW_RULE_STATUS_SEMANTIC_ERROR_TUNNEL_EXEMPT_WITH_GATEWAY                     = 1048817
        FW_RULE_STATUS_SEMANTIC_ERROR_TUNNEL_EXEMPT_VER                              = 1048818
        FW_RULE_STATUS_SEMANTIC_ERROR_ADDR_KEYWORD_VER                               = 1048819
        FW_RULE_STATUS_SEMANTIC_ERROR_KEY_MODULE_VER                                 = 1048820
        FW_RULE_STATUS_SEMANTIC_ERROR_APP_CONTAINER_PACKAGE_ID                       = 1048832
        FW_RULE_STATUS_SEMANTIC_ERROR_APP_CONTAINER_PACKAGE_ID_VER                   = 1048833
        FW_RULE_STATUS_SEMANTIC_ERROR_TRUST_TUPLE_KEYWORD_INCOMPATIBLE               = 1049088
        FW_RULE_STATUS_SEMANTIC_ERROR_TRUST_TUPLE_KEYWORD_INVALID                    = 1049089
        FW_RULE_STATUS_SEMANTIC_ERROR_TRUST_TUPLE_KEYWORD_VER                        = 1049090
        FW_RULE_STATUS_SEMANTIC_ERROR_INTERFACE_TYPES_VER                            = 1049345
        FW_RULE_STATUS_SEMANTIC_ERROR_NETNAMES_VER                                   = 1049601
        FW_RULE_STATUS_SEMANTIC_ERROR_SECURITY_REALM_ID_VER                          = 1049602
        FW_RULE_STATUS_SEMANTIC_ERROR_SYSTEMOS_GAMEOS_VER                            = 1049603
        FW_RULE_STATUS_SEMANTIC_ERROR_DEVMODE_VER                                    = 1049604
        FW_RULE_STATUS_SEMANTIC_ERROR_REMOTE_SERVERNAME_VER                          = 1049605
        FW_RULE_STATUS_SEMANTIC_ERROR_FQBN_VER                                       = 1049606
        FW_RULE_STATUS_SEMANTIC_ERROR_COMPARTMENT_ID_VER                             = 1049607
        FW_RULE_STATUS_SEMANTIC_ERROR_CALLOUT_AND_AUDIT_VER                          = 1049608
        FW_RULE_STATUS_SEMANTIC_ERROR_APPCONTAINER_LOOPBACK_VER                      = 1049609
        FW_RULE_STATUS_SEMANTIC_ERROR_PHASE1_AUTH_SET_ID                             = 1049856
        FW_RULE_STATUS_SEMANTIC_ERROR_PHASE2_CRYPTO_SET_ID                           = 1049872
        FW_RULE_STATUS_SEMANTIC_ERROR_PHASE1_CRYPTO_SET_ID                           = 1049873
        FW_RULE_STATUS_SEMANTIC_ERROR_FLAGS_KEY_MANAGER_DICTATE_VER                  = 1049874
        FW_RULE_STATUS_SEMANTIC_ERROR_FLAGS_KEY_MANAGER_NOTIFY_VER                   = 1049875
        FW_RULE_STATUS_SEMANTIC_ERROR_TRANSPORT_MACHINE_AUTHZ_VER                    = 1049876
        FW_RULE_STATUS_SEMANTIC_ERROR_TRANSPORT_USER_AUTHZ_VER                       = 1049877
        FW_RULE_STATUS_SEMANTIC_ERROR_TRANSPORT_MACHINE_AUTHZ_ON_TUNNEL              = 1049878
        FW_RULE_STATUS_SEMANTIC_ERROR_TRANSPORT_USER_AUTHZ_ON_TUNNEL                 = 1049879
        FW_RULE_STATUS_SEMANTIC_ERROR_PER_RULE_AND_GLOBAL_AUTHZ                      = 1049880
        FW_RULE_STATUS_SEMANTIC_ERROR_FLAGS_SECURITY_REALM                           = 1049881
        FW_RULE_STATUS_SEMANTIC_ERROR_SET_ID                                         = 1052672
        FW_RULE_STATUS_SEMANTIC_ERROR_IPSEC_PHASE                                    = 1052688
        FW_RULE_STATUS_SEMANTIC_ERROR_EMPTY_SUITES                                   = 1052704
        FW_RULE_STATUS_SEMANTIC_ERROR_PHASE1_AUTH_METHOD                             = 1052720
        FW_RULE_STATUS_SEMANTIC_ERROR_PHASE2_AUTH_METHOD                             = 1052721
        FW_RULE_STATUS_SEMANTIC_ERROR_AUTH_METHOD_ANONYMOUS                          = 1052722
        FW_RULE_STATUS_SEMANTIC_ERROR_AUTH_METHOD_DUPLICATE                          = 1052723
        FW_RULE_STATUS_SEMANTIC_ERROR_AUTH_METHOD_VER                                = 1052724
        FW_RULE_STATUS_SEMANTIC_ERROR_AUTH_SUITE_FLAGS                               = 1052736
        FW_RULE_STATUS_SEMANTIC_ERROR_HEALTH_CERT                                    = 1052737
        FW_RULE_STATUS_SEMANTIC_ERROR_AUTH_SIGNCERT_VER                              = 1052738
        FW_RULE_STATUS_SEMANTIC_ERROR_AUTH_INTERMEDIATE_CA_VER                       = 1052739
        FW_RULE_STATUS_SEMANTIC_ERROR_MACHINE_SHKEY                                  = 1052752
        FW_RULE_STATUS_SEMANTIC_ERROR_CA_NAME                                        = 1052768
        FW_RULE_STATUS_SEMANTIC_ERROR_MIXED_CERTS                                    = 1052769
        FW_RULE_STATUS_SEMANTIC_ERROR_NON_CONTIGUOUS_CERTS                           = 1052770
        FW_RULE_STATUS_SEMANTIC_ERROR_MIXED_CA_TYPE_IN_BLOCK                         = 1052771
        FW_RULE_STATUS_SEMANTIC_ERROR_MACHINE_USER_AUTH                              = 1052784
        FW_RULE_STATUS_SEMANTIC_ERROR_AUTH_CERT_CRITERIA_VER                         = 1052785
        FW_RULE_STATUS_SEMANTIC_ERROR_AUTH_CERT_CRITERIA_VER_MISMATCH                = 1052786
        FW_RULE_STATUS_SEMANTIC_ERROR_AUTH_CERT_CRITERIA_RENEWAL_HASH                = 1052787
        FW_RULE_STATUS_SEMANTIC_ERROR_AUTH_CERT_CRITERIA_INVALID_HASH                = 1052788
        FW_RULE_STATUS_SEMANTIC_ERROR_AUTH_CERT_CRITERIA_INVALID_EKU                 = 1052789
        FW_RULE_STATUS_SEMANTIC_ERROR_AUTH_CERT_CRITERIA_INVALID_NAME_TYPE           = 1052790
        FW_RULE_STATUS_SEMANTIC_ERROR_AUTH_CERT_CRITERIA_INVALID_NAME                = 1052791
        FW_RULE_STATUS_SEMANTIC_ERROR_AUTH_CERT_CRITERIA_INVALID_CRITERIA_TYPE       = 1052792
        FW_RULE_STATUS_SEMANTIC_ERROR_AUTH_CERT_CRITERIA_MISSING_CRITERIA            = 1052793
        FW_RULE_STATUS_SEMANTIC_ERROR_PROXY_SERVER                                   = 1052800
        FW_RULE_STATUS_SEMANTIC_ERROR_AUTH_PROXY_SERVER_VER                          = 1052801
        FW_RULE_STATUS_SEMANTIC_ERROR_PHASE1_CRYPTO_NON_DEFAULT_ID                   = 1069056
        FW_RULE_STATUS_SEMANTIC_ERROR_PHASE1_CRYPTO_FLAGS                            = 1069057
        FW_RULE_STATUS_SEMANTIC_ERROR_PHASE1_CRYPTO_TIMEOUT_MINUTES                  = 1069058
        FW_RULE_STATUS_SEMANTIC_ERROR_PHASE1_CRYPTO_TIMEOUT_SESSIONS                 = 1069059
        FW_RULE_STATUS_SEMANTIC_ERROR_PHASE1_CRYPTO_KEY_EXCHANGE                     = 1069060
        FW_RULE_STATUS_SEMANTIC_ERROR_PHASE1_CRYPTO_ENCRYPTION                       = 1069061
        FW_RULE_STATUS_SEMANTIC_ERROR_PHASE1_CRYPTO_HASH                             = 1069062
        FW_RULE_STATUS_SEMANTIC_ERROR_PHASE1_CRYPTO_ENCRYPTION_VER                   = 1069063
        FW_RULE_STATUS_SEMANTIC_ERROR_PHASE1_CRYPTO_HASH_VER                         = 1069064
        FW_RULE_STATUS_SEMANTIC_ERROR_PHASE1_CRYPTO_KEY_EXCH_VER                     = 1069065
        FW_RULE_STATUS_SEMANTIC_ERROR_PHASE2_CRYPTO_PFS                              = 1069088
        FW_RULE_STATUS_SEMANTIC_ERROR_PHASE2_CRYPTO_PROTOCOL                         = 1069089
        FW_RULE_STATUS_SEMANTIC_ERROR_PHASE2_CRYPTO_ENCRYPTION                       = 1069090
        FW_RULE_STATUS_SEMANTIC_ERROR_PHASE2_CRYPTO_HASH                             = 1069091
        FW_RULE_STATUS_SEMANTIC_ERROR_PHASE2_CRYPTO_TIMEOUT_MINUTES                  = 1069092
        FW_RULE_STATUS_SEMANTIC_ERROR_PHASE2_CRYPTO_TIMEOUT_KBYTES                   = 1069093
        FW_RULE_STATUS_SEMANTIC_ERROR_PHASE2_CRYPTO_ENCRYPTION_VER                   = 1069094
        FW_RULE_STATUS_SEMANTIC_ERROR_PHASE2_CRYPTO_HASH_VER                         = 1069095
        FW_RULE_STATUS_SEMANTIC_ERROR_PHASE2_CRYPTO_PFS_VER                          = 1069096
        FW_RULE_STATUS_SEMANTIC_ERROR_CRYPTO_ENCR_HASH                               = 1069120
        FW_RULE_STATUS_SEMANTIC_ERROR_CRYPTO_ENCR_HASH_COMPAT                        = 1069121
        FW_RULE_STATUS_SEMANTIC_ERROR_SCHEMA_VERSION                                 = 1069136
        FW_RULE_STATUS_SEMANTIC_ERROR_QUERY_OR_AND_CONDITIONS                        = 1073152
        FW_RULE_STATUS_SEMANTIC_ERROR_QUERY_AND_CONDITIONS                           = 1073153
        FW_RULE_STATUS_SEMANTIC_ERROR_QUERY_CONDITION_KEY                            = 1073154
        FW_RULE_STATUS_SEMANTIC_ERROR_QUERY_CONDITION_MATCH_TYPE                     = 1073155
        FW_RULE_STATUS_SEMANTIC_ERROR_QUERY_CONDITION_DATA_TYPE                      = 1073156
        FW_RULE_STATUS_SEMANTIC_ERROR_QUERY_CONDITION_KEY_AND_DATA_TYPE              = 1073157
        FW_RULE_STATUS_SEMANTIC_ERROR_QUERY_KEYS_PROTOCOL_PORT                       = 1073158
        FW_RULE_STATUS_SEMANTIC_ERROR_QUERY_KEY_PROFILE                              = 1073159
        FW_RULE_STATUS_SEMANTIC_ERROR_QUERY_KEY_STATUS                               = 1073160
        FW_RULE_STATUS_SEMANTIC_ERROR_QUERY_KEY_FILTERID                             = 1073161
        FW_RULE_STATUS_SEMANTIC_ERROR_QUERY_KEY_APP_PATH                             = 1073168
        FW_RULE_STATUS_SEMANTIC_ERROR_QUERY_KEY_PROTOCOL                             = 1073169
        FW_RULE_STATUS_SEMANTIC_ERROR_QUERY_KEY_LOCAL_PORT                           = 1073170
        FW_RULE_STATUS_SEMANTIC_ERROR_QUERY_KEY_REMOTE_PORT                          = 1073171
        FW_RULE_STATUS_SEMANTIC_ERROR_QUERY_KEY_SVC_NAME                             = 1073173
        FW_RULE_STATUS_SEMANTIC_ERROR_REQUIRE_IN_CLEAR_OUT_ON_TRANSPORT              = 1077248
        FW_RULE_STATUS_SEMANTIC_ERROR_BYPASS_TUNNEL_IF_SECURE_ON_TRANSPORT           = 1077249
        FW_RULE_STATUS_SEMANTIC_ERROR_AUTH_NOENCAP_ON_TUNNEL                         = 1077250
        FW_RULE_STATUS_SEMANTIC_ERROR_AUTH_NOENCAP_ON_PSK                            = 1077251
        FW_RULE_STATUS_SEMANTIC_ERROR_REMOTE_DYNAMIC_KEYWORD_ADDRESSES               = 1077252
        FW_RULE_STATUS_SEMANTIC_ERROR_PACKAGE_FAMILY_NAME_FIELD_NOT_FOUND            = 1077253
        FW_RULE_STATUS_RUNTIME_ERROR                                                 = 2097152
        FW_RULE_STATUS_RUNTIME_ERROR_PHASE1_AUTH_NOT_FOUND                           = 2097153
        FW_RULE_STATUS_RUNTIME_ERROR_PHASE2_AUTH_NOT_FOUND                           = 2097154
        FW_RULE_STATUS_RUNTIME_ERROR_PHASE2_CRYPTO_NOT_FOUND                         = 2097155
        FW_RULE_STATUS_RUNTIME_ERROR_AUTH_MCHN_SHKEY_MISMATCH                        = 2097156
        FW_RULE_STATUS_RUNTIME_ERROR_PHASE1_CRYPTO_NOT_FOUND                         = 2097157
        FW_RULE_STATUS_RUNTIME_ERROR_AUTH_NOENCAP_ON_TUNNEL                          = 2097158
        FW_RULE_STATUS_RUNTIME_ERROR_AUTH_NOENCAP_ON_PSK                             = 2097159
        FW_RULE_STATUS_RUNTIME_ERROR_KEY_MODULE_AUTH_MISMATCH                        = 2097160
        FW_RULE_STATUS_ERROR                                                         = 3670016
        FW_RULE_STATUS_ALL                                                           = 4294901760

class FW_RULE_STATUS_CLASS(NDRENUM):
    class enumItems(Enum):
        FW_RULE_STATUS_CLASS_OK                                                      = 65536
        FW_RULE_STATUS_CLASS_PARTIALLY_IGNORED                                       = 131072
        FW_RULE_STATUS_CLASS_IGNORED                                                 = 262144
        FW_RULE_STATUS_CLASS_PARSING_ERROR                                           = 524288
        FW_RULE_STATUS_CLASS_SEMANTIC_ERROR                                          = 1048576
        FW_RULE_STATUS_CLASS_RUNTIME_ERROR                                           = 2097152
        FW_RULE_STATUS_CLASS_ERROR                                                   = 3670016
        FW_RULE_STATUS_CLASS_ALL                                                     = 4294901760

class FW_OBJECT_CTRL_FLAG(NDRENUM):
    class enumItems(Enum):
        FW_OBJECT_CTRL_FLAG_INCLUDE_METADATA                                         = 1

class FW_ENFORCEMENT_STATE(NDRENUM):
    class enumItems(Enum):
        FW_ENFORCEMENT_STATE_INVALID                                                 = 0
        FW_ENFORCEMENT_STATE_FULL                                                    = 1
        FW_ENFORCEMENT_STATE_WF_OFF_IN_PROFILE                                       = 2
        FW_ENFORCEMENT_STATE_CATEGORY_OFF                                            = 3
        FW_ENFORCEMENT_STATE_DISABLED_OBJECT                                         = 4
        FW_ENFORCEMENT_STATE_INACTIVE_PROFILE                                        = 5
        FW_ENFORCEMENT_STATE_LOCAL_ADDRESS_RESOLUTION_EMPTY                          = 6
        FW_ENFORCEMENT_STATE_REMOTE_ADDRESS_RESOLUTION_EMPTY                         = 7
        FW_ENFORCEMENT_STATE_LOCAL_PORT_RESOLUTION_EMPTY                             = 8
        FW_ENFORCEMENT_STATE_REMOTE_PORT_RESOLUTION_EMPTY                            = 9
        FW_ENFORCEMENT_STATE_INTERFACE_RESOLUTION_EMPTY                              = 10
        FW_ENFORCEMENT_STATE_APPLICATION_RESOLUTION_EMPTY                            = 11
        FW_ENFORCEMENT_STATE_REMOTE_MACHINE_EMPTY                                    = 12
        FW_ENFORCEMENT_STATE_REMOTE_USER_EMPTY                                       = 13
        FW_ENFORCEMENT_STATE_LOCAL_GLOBAL_OPEN_PORTS_DISALLOWED                      = 14
        FW_ENFORCEMENT_STATE_LOCAL_AUTHORIZED_APPLICATIONS_DISALLOWED                = 15
        FW_ENFORCEMENT_STATE_LOCAL_FIREWALL_RULES_DISALLOWED                         = 16
        FW_ENFORCEMENT_STATE_LOCAL_CONSEC_RULES_DISALLOWED                           = 17
        FW_ENFORCEMENT_STATE_MISMATCHED_PLATFORM                                     = 18
        FW_ENFORCEMENT_STATE_OPTIMIZED_OUT                                           = 19
        FW_ENFORCEMENT_STATE_LOCAL_USER_EMPTY                                        = 20
        FW_ENFORCEMENT_STATE_TRANSPORT_MACHINE_SD_EMPTY                              = 21
        FW_ENFORCEMENT_STATE_TRANSPORT_USER_SD_EMPTY                                 = 22
        FW_ENFORCEMENT_STATE_TUPLE_RESOLUTION_EMPTY                                  = 23
        FW_ENFORCEMENT_STATE_NETNAME_RESOLUTION_EMPTY                                = 24
        FW_ENFORCEMENT_STATE_DUPLICATE                                               = 25
        FW_ENFORCEMENT_STATE_MAX                                                     = 26

class FW_OS_PLATFORM_OP(NDRENUM):
    class enumItems(Enum):
        FW_OS_PLATFORM_OP_EQ                                                         = 0
        FW_OS_PLATFORM_OP_GTEQ                                                       = 1
        FW_OS_PLATFORM_OP_MAX                                                        = 2
        FW_OS_PLATFORM_OP_FIELD_SIZE                                                 = 5
        FW_OS_PLATFORM_OP_FIELD_MASK                                                 = 248

class FW_RULE_ORIGIN_TYPE(NDRENUM):
    class enumItems(Enum):
        FW_RULE_ORIGIN_INVALID                                                       = 0
        FW_RULE_ORIGIN_LOCAL                                                         = 1
        FW_RULE_ORIGIN_GP                                                            = 2
        FW_RULE_ORIGIN_DYNAMIC                                                       = 3
        FW_RULE_ORIGIN_AUTOGEN                                                       = 4
        FW_RULE_ORIGIN_HARDCODED                                                     = 5
        FW_RULE_ORIGIN_MDM                                                           = 6
        FW_RULE_ORIGIN_MAX                                                           = 7
        FW_RULE_ORIGIN_HOST_LOCAL                                                    = 8
        FW_RULE_ORIGIN_HOST_GP                                                       = 9
        FW_RULE_ORIGIN_HOST_DYNAMIC                                                  = 10
        FW_RULE_ORIGIN_HOST_MDM                                                      = 11
        FW_RULE_ORIGIN_HOST_MAX                                                      = 12

class FW_ENUM_RULES_FLAGS(NDRENUM):
    class enumItems(Enum):
        FW_ENUM_RULES_FLAG_NONE                                                      = 0
        FW_ENUM_RULES_FLAG_RESOLVE_NAME                                              = 1
        FW_ENUM_RULES_FLAG_RESOLVE_DESCRIPTION                                       = 2
        FW_ENUM_RULES_FLAG_RESOLVE_APPLICATION                                       = 4
        FW_ENUM_RULES_FLAG_RESOLVE_KEYWORD                                           = 8
        FW_ENUM_RULES_FLAG_RESOLVE_GPO_NAME                                          = 16
        FW_ENUM_RULES_FLAG_EFFECTIVE                                                 = 32
        FW_ENUM_RULES_FLAG_INCLUDE_METADATA                                          = 64
        FW_ENUM_RULES_FLAG_MAX                                                       = 128

class FW_RULE_ACTION(NDRENUM):
    class enumItems(Enum):
        FW_RULE_ACTION_INVALID                                                       = 0
        FW_RULE_ACTION_ALLOW_BYPASS                                                  = 1
        FW_RULE_ACTION_BLOCK                                                         = 2
        FW_RULE_ACTION_ALLOW                                                         = 3
        FW_RULE_ACTION_MAX                                                           = 4

class FW_RULE_FLAGS(NDRENUM):
    class enumItems(Enum):
        FW_RULE_FLAGS_NONE                                                           = 0
        FW_RULE_FLAGS_ACTIVE                                                         = 1
        FW_RULE_FLAGS_AUTHENTICATE                                                   = 2
        FW_RULE_FLAGS_AUTHENTICATE_WITH_ENCRYPTION                                   = 4
        FW_RULE_FLAGS_ROUTEABLE_ADDRS_TRAVERSE                                       = 8
        FW_RULE_FLAGS_LOOSE_SOURCE_MAPPED                                            = 16
        FW_RULE_FLAGS_MAX_V2_1                                                       = 32
        FW_RULE_FLAGS_AUTH_WITH_NO_ENCAPSULATION                                     = 32
        FW_RULE_FLAGS_MAX_V2_9                                                       = 64
        FW_RULE_FLAGS_AUTH_WITH_ENC_NEGOTIATE                                        = 64
        FW_RULE_FLAGS_ROUTEABLE_ADDRS_TRAVERSE_DEFER_APP                             = 128
        FW_RULE_FLAGS_ROUTEABLE_ADDRS_TRAVERSE_DEFER_USER                            = 256
        FW_RULE_FLAGS_AUTHENTICATE_BYPASS_OUTBOUND                                   = 512
        FW_RULE_FLAGS_MAX_V2_10                                                      = 1024
        FW_RULE_FLAGS_ALLOW_PROFILE_CROSSING                                         = 1024
        FW_RULE_FLAGS_LOCAL_ONLY_MAPPED                                              = 2048
        FW_RULE_FLAGS_MAX_V2_20                                                      = 4096
        FW_RULE_FLAGS_LUA_CONDITIONAL_ACE                                            = 4096
        FW_RULE_FLAGS_BIND_TO_INTERFACE                                              = 8192
        FW_RULE_FLAGS_MAX                                                            = 16384

class FW_RULE_FLAGS2(NDRENUM):
    class enumItems(Enum):
        FW_RULE_FLAGS2_NONE                                                          = 0
        FW_RULE_FLAGS2_SYSTEMOS_ONLY                                                 = 1
        FW_RULE_FLAGS2_GAMEOS_ONLY                                                   = 2
        FW_RULE_FLAGS2_DEVMODE                                                       = 4
        FW_RULE_FLAGS_MAX_V2_26                                                      = 8
        FW_RULE_FLAGS2_NOT_USED_VALUE_8                                              = 8
        FW_RULE_FLAGS2_EMPTY_REMOTENAME                                              = 16
        FW_RULE_FLAGS2_NOT_REMOTENAME                                                = 32
        FW_RULE_FLAGS2_NOT_USED_VALUE_64                                             = 64
        FW_RULE_FLAGS2_CALLOUT_AND_AUDIT                                             = 128
        FW_RULE_FLAGS2_APP_LOOPBACK                                                  = 256
        FW_RULE_FLAGS2_NOT_USED_VALUE_512                                            = 512
        FW_RULE_FLAGS2_NOT_USED_VALUE_1024                                           = 1024
        FW_RULE_FLAGS2_NOT_USED_VALUE_2048                                           = 2048
        FW_RULE_FLAGS2_INDIRECT_NAME_RESOLVED                                        = 4096
        FW_RULE_FLAGS2_INDIRECT_DESCRIPTION_RESOLVED                                 = 8192
        FW_RULE_FLAGS2_MAX                                                           = 8192

class FW_PROFILE_CONFIG(NDRENUM):
    class enumItems(Enum):
        FW_PROFILE_CONFIG_INVALID                                                    = 0
        FW_PROFILE_CONFIG_ENABLE_FW                                                  = 1
        FW_PROFILE_CONFIG_DISABLE_STEALTH_MODE                                       = 2
        FW_PROFILE_CONFIG_SHIELDED                                                   = 3
        FW_PROFILE_CONFIG_DISABLE_UNICAST_RESPONSES_TO_MULTICAST_BROADCAST           = 4
        FW_PROFILE_CONFIG_LOG_DROPPED_PACKETS                                        = 5
        FW_PROFILE_CONFIG_LOG_SUCCESS_CONNECTIONS                                    = 6
        FW_PROFILE_CONFIG_LOG_IGNORED_RULES                                          = 7
        FW_PROFILE_CONFIG_LOG_MAX_FILE_SIZE                                          = 8
        FW_PROFILE_CONFIG_LOG_FILE_PATH                                              = 9
        FW_PROFILE_CONFIG_DISABLE_INBOUND_NOTIFICATIONS                              = 10
        FW_PROFILE_CONFIG_AUTH_APPS_ALLOW_USER_PREF_MERGE                            = 11
        FW_PROFILE_CONFIG_GLOBAL_PORTS_ALLOW_USER_PREF_MERGE                         = 12
        FW_PROFILE_CONFIG_ALLOW_LOCAL_POLICY_MERGE                                   = 13
        FW_PROFILE_CONFIG_ALLOW_LOCAL_IPSEC_POLICY_MERGE                             = 14
        FW_PROFILE_CONFIG_DISABLED_INTERFACES                                        = 15
        FW_PROFILE_CONFIG_DEFAULT_OUTBOUND_ACTION                                    = 16
        FW_PROFILE_CONFIG_DEFAULT_INBOUND_ACTION                                     = 17
        FW_PROFILE_CONFIG_DISABLE_STEALTH_MODE_IPSEC_SECURED_PACKET_EXEMPTION        = 18
        FW_PROFILE_CONFIG_MAX                                                        = 19

class FW_GLOBAL_CONFIG_IPSEC_EXEMPT_VALUES(NDRENUM):
    class enumItems(Enum):
        FW_GLOBAL_CONFIG_IPSEC_EXEMPT_NONE                                           = 0
        FW_GLOBAL_CONFIG_IPSEC_EXEMPT_NEIGHBOR_DISC                                  = 1
        FW_GLOBAL_CONFIG_IPSEC_EXEMPT_ICMP                                           = 2
        FW_GLOBAL_CONFIG_IPSEC_EXEMPT_ROUTER_DISC                                    = 4
        FW_GLOBAL_CONFIG_IPSEC_EXEMPT_NEIGHBOR_DISC_RFC                              = 5
        FW_GLOBAL_CONFIG_IPSEC_EXEMPT_DHCP                                           = 8
        FW_GLOBAL_CONFIG_IPSEC_EXEMPT_MAX                                            = 16

class FW_GLOBAL_CONFIG_PRESHARED_KEY_ENCODING_VALUES(NDRENUM):
    class enumItems(Enum):
        FW_GLOBAL_CONFIG_PRESHARED_KEY_ENCODING_NONE                                 = 0
        FW_GLOBAL_CONFIG_PRESHARED_KEY_ENCODING_UTF_8                                = 1
        FW_GLOBAL_CONFIG_PRESHARED_KEY_ENCODING_MAX                                  = 2

class FW_GLOBAL_CONFIG_IPSEC_THROUGH_NAT_VALUES(NDRENUM):
    class enumItems(Enum):
        FW_GLOBAL_CONFIG_IPSEC_THROUGH_NAT_NEVER                                     = 0
        FW_GLOBAL_CONFIG_IPSEC_THROUGH_NAT_SERVER_BEHIND_NAT                         = 1
        FW_GLOBAL_CONFIG_IPSEC_THROUGH_NAT_SERVER_AND_CLIENT_BEHIND_NAT              = 2
        FW_GLOBAL_CONFIG_IPSEC_THROUGH_NAT_MAX                                       = 3

class FW_GLOBAL_CONFIG_ENABLE_PACKET_QUEUE_FLAGS(NDRENUM):
    class enumItems(Enum):
        FW_GLOBAL_CONFIG_PACKET_QUEUE_NONE                                           = 0
        FW_GLOBAL_CONFIG_PACKET_QUEUE_INBOUND                                        = 1
        FW_GLOBAL_CONFIG_PACKET_QUEUE_FORWARD                                        = 2
        FW_GLOBAL_CONFIG_PACKET_QUEUE_MAX                                            = 3

class FW_GLOBAL_CONFIG(NDRENUM):
    class enumItems(Enum):
        FW_GLOBAL_CONFIG_INVALID                                                     = 0
        FW_GLOBAL_CONFIG_POLICY_VERSION_SUPPORTED                                    = 1
        FW_GLOBAL_CONFIG_CURRENT_PROFILE                                             = 2
        FW_GLOBAL_CONFIG_DISABLE_STATEFUL_FTP                                        = 3
        FW_GLOBAL_CONFIG_DISABLE_STATEFUL_PPTP                                       = 4
        FW_GLOBAL_CONFIG_SA_IDLE_TIME                                                = 5
        FW_GLOBAL_CONFIG_PRESHARED_KEY_ENCODING                                      = 6
        FW_GLOBAL_CONFIG_IPSEC_EXEMPT                                                = 7
        FW_GLOBAL_CONFIG_CRL_CHECK                                                   = 8
        FW_GLOBAL_CONFIG_IPSEC_THROUGH_NAT                                           = 9
        FW_GLOBAL_CONFIG_POLICY_VERSION                                              = 10
        FW_GLOBAL_CONFIG_BINARY_VERSION_SUPPORTED                                    = 11
        FW_GLOBAL_CONFIG_IPSEC_TUNNEL_REMOTE_MACHINE_AUTHORIZATION_LIST              = 12
        FW_GLOBAL_CONFIG_IPSEC_TUNNEL_REMOTE_USER_AUTHORIZATION_LIST                 = 13
        FW_GLOBAL_CONFIG_OPPORTUNISTICALLY_MATCH_AUTH_SET_PER_KM                     = 14
        FW_GLOBAL_CONFIG_IPSEC_TRANSPORT_REMOTE_MACHINE_AUTHORIZATION_LIST           = 15
        FW_GLOBAL_CONFIG_IPSEC_TRANSPORT_REMOTE_USER_AUTHORIZATION_LIST              = 16
        FW_GLOBAL_CONFIG_ENABLE_PACKET_QUEUE                                         = 17
        FW_GLOBAL_CONFIG_MAX                                                         = 18

class FW_CONFIG_FLAGS(NDRENUM):
    class enumItems(Enum):
        FW_CONFIG_FLAG_RETURN_DEFAULT_IF_NOT_FOUND                                   = 1

class FW_RULE_CATEGORY(NDRENUM):
    class enumItems(Enum):
        FW_RULE_CATEGORY_BOOT                                                        = 0
        FW_RULE_CATEGORY_STEALTH                                                     = 1
        FW_RULE_CATEGORY_FIREWALL                                                    = 2
        FW_RULE_CATEGORY_CONSEC                                                      = 3
        FW_RULE_CATEGORY_MAX                                                         = 4

class FW_IP_VERSION(NDRENUM):
    class enumItems(Enum):
        FW_IP_VERSION_INVALID                                                        = 0
        FW_IP_VERSION_V4                                                             = 1
        FW_IP_VERSION_V6                                                             = 2
        FW_IP_VERSION_MAX                                                            = 3

class FW_IPSEC_PHASE(NDRENUM):
    class enumItems(Enum):
        FW_IPSEC_PHASE_INVALID                                                       = 0
        FW_IPSEC_PHASE_1                                                             = 1
        FW_IPSEC_PHASE_2                                                             = 2
        FW_IPSEC_PHASE_MAX                                                           = 3

class FW_CS_RULE_FLAGS(NDRENUM):
    class enumItems(Enum):
        FW_CS_RULE_FLAGS_NONE                                                        = 0
        FW_CS_RULE_FLAGS_ACTIVE                                                      = 1
        FW_CS_RULE_FLAGS_DTM                                                         = 2
        FW_CS_RULE_FLAGS_TUNNEL_BYPASS_IF_ENCRYPTED                                  = 8
        FW_CS_RULE_FLAGS_OUTBOUND_CLEAR                                              = 16
        FW_CS_RULE_FLAGS_APPLY_AUTHZ                                                 = 32
        FW_CS_RULE_FLAGS_KEY_MANAGER_ALLOW_DICTATE_KEY                               = 64
        FW_CS_RULE_FLAGS_KEY_MANAGER_ALLOW_NOTIFY_KEY                                = 128
        FW_CS_RULE_FLAGS_SECURITY_REALM                                              = 256
        FW_CS_RULE_FLAGS_TUNNEL_TYPE_POINT_TO_SITE                                   = 512
        FW_CS_RULE_FLAGS_MAX                                                         = 1024
        FW_CS_RULE_FLAGS_MAX_V2_1                                                    = 2
        FW_CS_RULE_FLAGS_MAX_V2_8                                                    = 4
        FW_CS_RULE_FLAGS_MAX_V2_10                                                   = 64
        FW_CS_RULE_FLAGS_MAX_V2_20                                                   = 256

class FW_CS_RULE_ACTION(NDRENUM):
    class enumItems(Enum):
        FW_CS_RULE_ACTION_INVALID                                                    = 0
        FW_CS_RULE_ACTION_SECURE_SERVER                                              = 1
        FW_CS_RULE_ACTION_BOUNDARY                                                   = 2
        FW_CS_RULE_ACTION_SECURE                                                     = 3
        FW_CS_RULE_ACTION_DO_NOT_SECURE                                              = 4
        FW_CS_RULE_ACTION_MAX                                                        = 5

class FW_KEY_MODULE(NDRENUM):
    class enumItems(Enum):
        FW_KEY_MODULE_DEFAULT                                                        = 0
        FW_KEY_MODULE_IKEv1                                                          = 1
        FW_KEY_MODULE_AUTHIP                                                         = 2
        FW_KEY_MODULE_IKEv2                                                          = 4
        FW_KEY_MODULE_MAX                                                            = 8

class FW_AUTH_METHOD(NDRENUM):
    class enumItems(Enum):
        FW_AUTH_METHOD_INVALID                                                       = 0
        FW_AUTH_METHOD_ANONYMOUS                                                     = 1
        FW_AUTH_METHOD_MACHINE_KERB                                                  = 2
        FW_AUTH_METHOD_MACHINE_SHKEY                                                 = 3
        FW_AUTH_METHOD_MACHINE_NTLM                                                  = 4
        FW_AUTH_METHOD_MACHINE_CERT                                                  = 5
        FW_AUTH_METHOD_USER_KERB                                                     = 6
        FW_AUTH_METHOD_USER_CERT                                                     = 7
        FW_AUTH_METHOD_USER_NTLM                                                     = 8
        FW_AUTH_METHOD_MACHINE_RESERVED                                              = 9
        FW_AUTH_METHOD_USER_RESERVED                                                 = 10
        FW_AUTH_METHOD_MAX                                                           = 11
        FW_AUTH_METHOD_MAX_2_10                                                      = 9

class FW_AUTH_SUITE_FLAGS(NDRENUM):
    class enumItems(Enum):
        FW_AUTH_SUITE_FLAGS_NONE                                                     = 0
        FW_AUTH_SUITE_FLAGS_CERT_EXCLUDE_CA_NAME                                     = 1
        FW_AUTH_SUITE_FLAGS_HEALTH_CERT                                              = 2
        FW_AUTH_SUITE_FLAGS_PERFORM_CERT_ACCOUNT_MAPPING                             = 4
        FW_AUTH_SUITE_FLAGS_CERT_SIGNING_ECDSA256                                    = 8
        FW_AUTH_SUITE_FLAGS_CERT_SIGNING_ECDSA384                                    = 16
        FW_AUTH_SUITE_FLAGS_MAX_V2_1                                                 = 32
        FW_AUTH_SUITE_FLAGS_INTERMEDIATE_CA                                          = 32
        FW_AUTH_SUITE_FLAGS_MAX_V2_10                                                = 64
        FW_AUTH_SUITE_FLAGS_ALLOW_PROXY                                              = 64
        FW_AUTH_SUITE_FLAGS_MAX                                                      = 128

class FW_CERT_CRITERIA_NAME_TYPE(NDRENUM):
    class enumItems(Enum):
        FW_CERT_CRITERIA_NAME_NONE                                                   = 0
        FW_CERT_CRITERIA_NAME_DNS                                                    = 1
        FW_CERT_CRITERIA_NAME_UPN                                                    = 2
        FW_CERT_CRITERIA_NAME_RFC822                                                 = 3
        FW_CERT_CRITERIA_NAME_CN                                                     = 4
        FW_CERT_CRITERIA_NAME_OU                                                     = 5
        FW_CERT_CRITERIA_NAME_O                                                      = 6
        FW_CERT_CRITERIA_NAME_DC                                                     = 7
        FW_CERT_CRITERIA_NAME_MAX                                                    = 8

class FW_CERT_CRITERIA_TYPE(NDRENUM):
    class enumItems(Enum):
        FW_CERT_CRITERIA_TYPE_BOTH                                                   = 0
        FW_CERT_CRITERIA_TYPE_SELECTION                                              = 1
        FW_CERT_CRITERIA_TYPE_VALIDATION                                             = 2
        FW_CERT_CRITERIA_TYPE_MAX                                                    = 3

class FW_AUTH_CERT_CRITERIA_FLAGS(NDRENUM):
    class enumItems(Enum):
        FW_AUTH_CERT_CRITERIA_FLAGS_NONE                                             = 0
        FW_AUTH_CERT_CRITERIA_FLAGS_FOLLOW_RENEWAL                                   = 1
        FW_AUTH_CERT_CRITERIA_FLAGS_MAX                                              = 2

class FW_AUTH_SET_FLAGS(NDRENUM):
    class enumItems(Enum):
        FW_AUTH_SET_FLAGS_NONE                                                       = 0
        FW_AUTH_SET_FLAGS_MAX                                                        = 1

class FW_CRYPTO_KEY_EXCHANGE_TYPE(NDRENUM):
    class enumItems(Enum):
        FW_CRYPTO_KEY_EXCHANGE_NONE                                                  = 0
        FW_CRYPTO_KEY_EXCHANGE_DH1                                                   = 1
        FW_CRYPTO_KEY_EXCHANGE_DH2                                                   = 2
        FW_CRYPTO_KEY_EXCHANGE_ECDH256                                               = 3
        FW_CRYPTO_KEY_EXCHANGE_ECDH384                                               = 4
        FW_CRYPTO_KEY_EXCHANGE_DH2048                                                = 5
        FW_CRYPTO_KEY_EXCHANGE_DH24                                                  = 6
        FW_CRYPTO_KEY_EXCHANGE_MAX                                                   = 7
        FW_CRYPTO_KEY_EXCHANGE_DH14                                                  = 5
        FW_CRYPTO_KEY_EXCHANGE_MAX_V2_10                                             = 6

class FW_CRYPTO_ENCRYPTION_TYPE(NDRENUM):
    class enumItems(Enum):
        FW_CRYPTO_ENCRYPTION_NONE                                                    = 0
        FW_CRYPTO_ENCRYPTION_DES                                                     = 1
        FW_CRYPTO_ENCRYPTION_3DES                                                    = 2
        FW_CRYPTO_ENCRYPTION_AES128                                                  = 3
        FW_CRYPTO_ENCRYPTION_AES192                                                  = 4
        FW_CRYPTO_ENCRYPTION_AES256                                                  = 5
        FW_CRYPTO_ENCRYPTION_AES_GCM128                                              = 6
        FW_CRYPTO_ENCRYPTION_AES_GCM192                                              = 7
        FW_CRYPTO_ENCRYPTION_AES_GCM256                                              = 8
        FW_CRYPTO_ENCRYPTION_MAX                                                     = 9
        FW_CRYPTO_ENCRYPTION_MAX_V2_0                                                = 6

class FW_CRYPTO_HASH_TYPE(NDRENUM):
    class enumItems(Enum):
        FW_CRYPTO_HASH_NONE                                                          = 0
        FW_CRYPTO_HASH_MD5                                                           = 1
        FW_CRYPTO_HASH_SHA1                                                          = 2
        FW_CRYPTO_HASH_SHA256                                                        = 3
        FW_CRYPTO_HASH_SHA384                                                        = 4
        FW_CRYPTO_HASH_AES_GMAC128                                                   = 5
        FW_CRYPTO_HASH_AES_GMAC192                                                   = 6
        FW_CRYPTO_HASH_AES_GMAC256                                                   = 7
        FW_CRYPTO_HASH_MAX                                                           = 8
        FW_CRYPTO_HASH_MAX_V2_0                                                      = 3

class FW_CRYPTO_PROTOCOL_TYPE(NDRENUM):
    class enumItems(Enum):
        FW_CRYPTO_PROTOCOL_INVALID                                                   = 0
        FW_CRYPTO_PROTOCOL_AH                                                        = 1
        FW_CRYPTO_PROTOCOL_ESP                                                       = 2
        FW_CRYPTO_PROTOCOL_BOTH                                                      = 3
        FW_CRYPTO_PROTOCOL_AUTH_NO_ENCAP                                             = 4
        FW_CRYPTO_PROTOCOL_MAX                                                       = 5
        FW_CRYPTO_PROTOCOL_MAX_2_1                                                   = 4

class FW_CRYPTO_SET_FLAGS(NDRENUM):
    class enumItems(Enum):
        FW_CRYPTO_SET_FLAGS_NONE                                                     = 0
        FW_CRYPTO_SET_FLAGS_MAX                                                      = 1

class FW_PHASE1_CRYPTO_FLAGS(NDRENUM):
    class enumItems(Enum):
        FW_PHASE1_CRYPTO_FLAGS_NONE                                                  = 0
        FW_PHASE1_CRYPTO_FLAGS_DO_NOT_SKIP_DH                                        = 1
        FW_PHASE1_CRYPTO_FLAGS_MAX                                                   = 2

class FW_PHASE2_CRYPTO_PFS(NDRENUM):
    class enumItems(Enum):
        FW_PHASE2_CRYPTO_PFS_INVALID                                                 = 0
        FW_PHASE2_CRYPTO_PFS_DISABLE                                                 = 1
        FW_PHASE2_CRYPTO_PFS_PHASE1                                                  = 2
        FW_PHASE2_CRYPTO_PFS_DH1                                                     = 3
        FW_PHASE2_CRYPTO_PFS_DH2                                                     = 4
        FW_PHASE2_CRYPTO_PFS_DH2048                                                  = 5
        FW_PHASE2_CRYPTO_PFS_ECDH256                                                 = 6
        FW_PHASE2_CRYPTO_PFS_ECDH384                                                 = 7
        FW_PHASE2_CRYPTO_PFS_DH24                                                    = 8
        FW_PHASE2_CRYPTO_PFS_MAX                                                     = 9
        FW_PHASE2_CRYPTO_PFS_MAX_V2_10                                               = 8

class FW_PHASE1_KEY_MODULE_TYPE(NDRENUM):
    class enumItems(Enum):
        FW_PHASE1_KEY_MODULE_INVALID                                                 = 0
        FW_PHASE1_KEY_MODULE_IKE                                                     = 1
        FW_PHASE1_KEY_MODULE_AUTH_IP                                                 = 2
        FW_PHASE1_KEY_MODULE_IKEV2                                                   = 3
        FW_PHASE1_KEY_MODULE_MAX                                                     = 4

class FW_PHASE2_TRAFFIC_TYPE(NDRENUM):
    class enumItems(Enum):
        FW_PHASE2_TRAFFIC_TYPE_INVALID                                               = 0
        FW_PHASE2_TRAFFIC_TYPE_TRANSPORT                                             = 1
        FW_PHASE2_TRAFFIC_TYPE_TUNNEL                                                = 2
        FW_PHASE2_TRAFFIC_TYPE_MAX                                                   = 3

class FW_MATCH_KEY(NDRENUM):
    class enumItems(Enum):
        FW_MATCH_KEY_PROFILE                                                         = 0
        FW_MATCH_KEY_STATUS                                                          = 1
        FW_MATCH_KEY_OBJECTID                                                        = 2
        FW_MATCH_KEY_FILTERID                                                        = 3
        FW_MATCH_KEY_APP_PATH                                                        = 4
        FW_MATCH_KEY_PROTOCOL                                                        = 5
        FW_MATCH_KEY_LOCAL_PORT                                                      = 6
        FW_MATCH_KEY_REMOTE_PORT                                                     = 7
        FW_MATCH_KEY_GROUP                                                           = 8
        FW_MATCH_KEY_SVC_NAME                                                        = 9
        FW_MATCH_KEY_DIRECTION                                                       = 10
        FW_MATCH_KEY_LOCAL_USER_OWNER                                                = 11
        FW_MATCH_KEY_PACKAGE_ID                                                      = 12
        FW_MATCH_KEY_FQBN                                                            = 13
        FW_MATCH_KEY_COMPARTMENT_ID                                                  = 14
        FW_MATCH_KEY_REMOTE_USER_AUTH_LIST                                           = 15
        FW_MATCH_KEY_PACKAGE_FAMILY_NAME                                             = 16
        FW_MATCH_KEY_MAX                                                             = 17

class FW_DATA_TYPE(NDRENUM):
    class enumItems(Enum):
        FW_DATA_TYPE_EMPTY                                                           = 0
        FW_DATA_TYPE_UINT8                                                           = 1
        FW_DATA_TYPE_UINT16                                                          = 2
        FW_DATA_TYPE_UINT32                                                          = 3
        FW_DATA_TYPE_UINT64                                                          = 4
        FW_DATA_TYPE_UNICODE_STRING                                                  = 5

class FW_MATCH_TYPE(NDRENUM):
    class enumItems(Enum):
        FW_MATCH_TYPE_TRAFFIC_MATCH                                                  = 0
        FW_MATCH_TYPE_EQUAL                                                          = 1
        FW_MATCH_TYPE_MAX                                                            = 2

class FW_HYPERV_PORT_FLAGS(NDRENUM):
    class enumItems(Enum):
        FW_HYPERV_PORT_FLAGS_NONE                                                    = 0
        FW_HYPERV_PORT_FLAGS_CONSTRAINED_INTERFACE                                   = 1
        FW_HYPERV_PORT_FLAGS_MAX                                                     = 2

class FW_HYPERV_NETWORK_TYPE(NDRENUM):
    class enumItems(Enum):
        FW_HYPERV_NETWORK_TYPE_INVALID                                               = 0
        FW_HYPERV_NETWORK_TYPE_FSE                                                   = 1
        FW_HYPERV_NETWORK_TYPE_NAT                                                   = 2
        FW_HYPERV_NETWORK_TYPE_MAX                                                   = 4

class FW_HYPERV_VM_CONFIG(NDRENUM):
    class enumItems(Enum):
        FW_HYPERV_VM_CONFIG_INVALID                                                  = 0
        FW_HYPERV_VM_CONFIG_LOOPBACK_ENABLED                                         = 1
        FW_HYPERV_VM_CONFIG_ALLOW_HOST_POLICY_MERGE                                  = 2
        FW_HYPERV_VM_CONFIG_MAX                                                      = 3

class FW_HYPERV_PROFILE_CONFIG(NDRENUM):
    class enumItems(Enum):
        FW_HYPERV_PROFILE_CONFIG_INVALID                                             = 0
        FW_HYPERV_PROFILE_CONFIG_ENABLED                                             = 1
        FW_HYPERV_PROFILE_CONFIG_ALLOW_LOCAL_POLICY_MERGE                            = 2
        FW_HYPERV_PROFILE_CONFIG_MAX                                                 = 3

class FW_HYPERV_RULE_PORT_ENFORCEMENT_STATE(NDRENUM):
    class enumItems(Enum):
        FW_HYPERV_RULE_PORT_ENFORCEMENT_STATE_INVALID                                = 0
        FW_HYPERV_RULE_PORT_ENFORCEMENT_STATE_ENFORCED                               = 1
        FW_HYPERV_RULE_PORT_ENFORCEMENT_STATE_ERROR                                  = 2
        FW_HYPERV_RULE_PORT_ENFORCEMENT_STATE_ENFORCED_EMPTY_RESOLUTION              = 3
        FW_HYPERV_RULE_PORT_ENFORCEMENT_STATE_PORT_NOT_FOUND                         = 4
        FW_HYPERV_RULE_PORT_ENFORCEMENT_STATE_RULE_INACTIVE                          = 5
        FW_HYPERV_RULE_PORT_ENFORCEMENT_STATE_VM_CREATOR_NOT_APPLICABLE              = 6
        FW_HYPERV_RULE_PORT_ENFORCEMENT_STATE_PROFILE_NOT_APPLICABLE                 = 7
        FW_HYPERV_RULE_PORT_ENFORCEMENT_STATE_PROFILE_DISABLED                       = 8
        FW_HYPERV_RULE_PORT_ENFORCEMENT_STATE_PROFILE_LOCAL_RULES_DISALLOWED         = 9
        FW_HYPERV_RULE_PORT_ENFORCEMENT_STATE_CONSTRAINED_INTERFACE_NOT_APPLICABLE   = 10
        FW_HYPERV_RULE_PORT_ENFORCEMENT_STATE_NAT_INBOUND_NOT_APPLICABLE             = 11
        FW_HYPERV_RULE_PORT_ENFORCEMENT_STATE_NAT_LOCAL_ADDRESS_NOT_SUPPORTED        = 12
        FW_HYPERV_RULE_PORT_ENFORCEMENT_STATE_HOST_POLICY_MERGE_DISABLED             = 13
        FW_HYPERV_RULE_PORT_ENFORCEMENT_STATE_HOST_FIREWALL_PROFILE_DISABLED         = 14
        FW_HYPERV_RULE_PORT_ENFORCEMENT_STATE_HOST_FIREWALL_DEFAULT_ACTION_CONFLICT  = 15
        FW_HYPERV_RULE_PORT_ENFORCEMENT_STATE_HOST_FIREWALL_PROFILE_LOCAL_POLICY_MERGE_DISABLED = 16
        FW_HYPERV_RULE_PORT_ENFORCEMENT_STATE_HOST_FIREWALL_RULE_CATEGORY_DISABLED   = 17
        FW_HYPERV_RULE_PORT_ENFORCEMENT_STATE_MAX                                    = 18

class FW_HYPERV_RULE_STATUS(NDRENUM):
    class enumItems(Enum):
        FW_HYPERV_RULE_STATUS_INVALID                                                = 0
        FW_HYPERV_RULE_STATUS_OK                                                     = 1
        FW_HYPERV_RULE_STATUS_PARTIALLY_ENFORCED                                     = 2
        FW_HYPERV_RULE_STATUS_NO_APPLICABLE_PORTS                                    = 3
        FW_HYPERV_RULE_STATUS_PARSING_ERROR                                          = 4
        FW_HYPERV_RULE_STATUS_ERROR                                                  = 5
        FW_HYPERV_RULE_STATUS_MAX                                                    = 6

class FW_HYPERV_RULE_FLAGS(NDRENUM):
    class enumItems(Enum):
        FW_HYPERV_RULE_FLAGS_NONE                                                    = 0
        FW_HYPERV_RULE_FLAGS_ACTIVE                                                  = 1
        FW_HYPERV_RULE_FLAGS_CONSTRAINED_INTERFACE                                   = 2
        FW_HYPERV_RULE_FLAGS_MAX_V2_32                                               = 4
        FW_HYPERV_RULE_FLAGS_INTERNAL_MIN_PRIORITY                                   = 4
        FW_HYPERV_RULE_FLAGS_MAX_V2_33                                               = 8
        FW_HYPERV_RULE_FLAGS_MAX                                                     = 8

################################################################################
# STRUCTURES
################################################################################

class handle_t(NDRSTRUCT):
    structure = (
         ('context_handle_attributes',ULONG),
         ('context_handle_uuid',UUID),
    )

    def __init__(self, data=None, isNDR64=False):
        NDRSTRUCT.__init__(self, data, isNDR64)
        self['context_handle_uuid'] = b'\x00'*16

    def isNull(self):
        return self['context_handle_uuid'] == b'\x00'*16

FW_CONN_HANDLE = handle_t

class FW_POLICY_STORE_HANDLE(NDRSTRUCT):
    structure =  (
        ('Data','20s=""'),
    )
    def getAlignment(self):
        return 1

class PFW_POLICY_STORE_HANDLE(NDRPOINTER):
    referent = (
        ('Data', FW_POLICY_STORE_HANDLE),
    )

FW_PRODUCT_HANDLE = handle_t

class PVOID(NDRPOINTER):
    referent = (
        ('Data', BYTE),
    )

class BYTE_ARRAY(NDRUniConformantArray):
    item = 'c'

class PBYTE_ARRAY(NDRPOINTER):
    referent = (
        ('Data', BYTE_ARRAY),
    )

class DWORD_ARRAY(NDRUniConformantArray):
    item = DWORD

class PDWORD_ARRAY(NDRPOINTER):
    referent = (
        ('Data', DWORD_ARRAY),
    )

class WORD_ARRAY(NDRUniConformantArray):
    item = WORD

class PWORD_ARRAY(NDRPOINTER):
    referent = (
        ('Data', WORD_ARRAY),
    )

class FW_IPV4_SUBNET(NDRSTRUCT):
    structure = (
        ('dwAddress', DWORD),
        ('dwSubNetMask', DWORD),
    )

class FW_IPV4_SUBNET_ARRAY(NDRUniConformantArray):
    item = FW_IPV4_SUBNET

class PFW_IPV4_SUBNET_ARRAY(NDRPOINTER):
    referent = (
        ('Data', FW_IPV4_SUBNET_ARRAY),
    )

class FW_IPV4_SUBNET_LIST(NDRSTRUCT):
    structure = (
        ('dwNumEntries', DWORD),
        ('pSubNets', PFW_IPV4_SUBNET_ARRAY),
    )

class FW_IPV6_SUBNET(NDRSTRUCT):
    structure = (
        ('Address', '16s=b"\\x00"*16'),
        ('dwNumPrefixBits', DWORD),
    )

class FW_IPV6_SUBNET_ARRAY(NDRUniConformantArray):
    item = FW_IPV6_SUBNET

class PFW_IPV6_SUBNET_ARRAY(NDRPOINTER):
    referent = (
        ('Data', FW_IPV6_SUBNET_ARRAY),
    )

class FW_IPV6_SUBNET_LIST(NDRSTRUCT):
    structure = (
        ('dwNumEntries', DWORD),
        ('pSubNets', PFW_IPV6_SUBNET_ARRAY),
    )

class FW_IPV4_ADDRESS_RANGE(NDRSTRUCT):
    structure = (
        ('dwBegin', DWORD),
        ('dwEnd', DWORD),
    )

class FW_IPV6_ADDRESS_RANGE(NDRSTRUCT):
    structure = (
        ('Begin', '16s=b"\\x00"*16'),
        ('End', '16s=b"\\x00"*16'),
    )

class FW_IPV4_ADDRESS_RANGE_ARRAY(NDRUniConformantArray):
    item = FW_IPV4_ADDRESS_RANGE

class PFW_IPV4_ADDRESS_RANGE_ARRAY(NDRPOINTER):
    referent = (
        ('Data', FW_IPV4_ADDRESS_RANGE_ARRAY),
    )

class FW_IPV4_RANGE_LIST(NDRSTRUCT):
    structure = (
        ('dwNumEntries', DWORD),
        ('pRanges', PFW_IPV4_ADDRESS_RANGE_ARRAY),
    )

class FW_IPV6_ADDRESS_RANGE_ARRAY(NDRUniConformantArray):
    item = FW_IPV6_ADDRESS_RANGE

class PFW_IPV6_ADDRESS_RANGE_ARRAY(NDRPOINTER):
    referent = (
        ('Data', FW_IPV6_ADDRESS_RANGE_ARRAY),
    )

class FW_IPV6_RANGE_LIST(NDRSTRUCT):
    structure = (
        ('dwNumEntries', DWORD),
        ('pRanges', PFW_IPV6_ADDRESS_RANGE_ARRAY),
    )

class FW_PORT_RANGE(NDRSTRUCT):
    structure = (
        ('wBegin', WORD),
        ('wEnd', WORD),
    )

class FW_PORT_RANGE_ARRAY(NDRUniConformantArray):
    item = FW_PORT_RANGE

class PFW_PORT_RANGE_ARRAY(NDRPOINTER):
    referent = (
        ('Data', FW_PORT_RANGE_ARRAY),
    )

class FW_PORT_RANGE_LIST(NDRSTRUCT):
    structure = (
        ('dwNumEntries', DWORD),
        ('pPorts', PFW_PORT_RANGE_ARRAY),
    )

class FW_PORTS(NDRSTRUCT):
    structure = (
        ('wPortKeywords', WORD),
        ('Ports', FW_PORT_RANGE_LIST),
    )

class FW_ICMP_TYPE_CODE(NDRSTRUCT):
    structure = (
        ('bType', BYTE),
        ('wCode', WORD),
    )

class FW_ICMP_TYPE_CODE_ARRAY(NDRUniConformantArray):
    item = FW_ICMP_TYPE_CODE

class PFW_ICMP_TYPE_CODE_ARRAY(NDRPOINTER):
    referent = (
        ('Data', FW_ICMP_TYPE_CODE_ARRAY),
    )

class FW_ICMP_TYPE_CODE_LIST(NDRSTRUCT):
    structure = (
        ('dwNumEntries', DWORD),
        ('pEntries', PFW_ICMP_TYPE_CODE_ARRAY),
    )

class GUID_ARRAY(NDRUniConformantArray):
    item = GUID

class PGUID_ARRAY(NDRPOINTER):
    referent = (
        ('Data', GUID_ARRAY),
    )

class FW_INTERFACE_LUIDS(NDRSTRUCT):
    structure = (
        ('dwNumLUIDs', DWORD),
        ('pLUIDs', PGUID_ARRAY),
    )

class PFW_INTERFACE_LUIDS(NDRPOINTER):
    referent = (
        ('Data', FW_INTERFACE_LUIDS),
    )

class FW_ADDRESSES(NDRSTRUCT):
    structure = (
        ('dwV4AddressKeywords', DWORD),
        ('dwV6AddressKeywords', DWORD),
        ('V4SubNets', FW_IPV4_SUBNET_LIST),
        ('V4Ranges', FW_IPV4_RANGE_LIST),
        ('V6SubNets', FW_IPV6_SUBNET_LIST),
        ('V6Ranges', FW_IPV6_RANGE_LIST),
    )

class FW_DYNAMIC_KEYWORD_ADDRESS_ID_LIST(NDRSTRUCT):
    structure = (
        ('dwNumIds', DWORD),
        ('ids', PGUID_ARRAY),
    )

class FW_DYNAMIC_KEYWORD_ADDRESS0(NDRSTRUCT):
    structure = (
        ('id', GUID),
        ('keyword', LPWSTR),
        ('flags', DWORD),
        ('addresses', LPWSTR),
    )

class FW_DYNAMIC_KEYWORD_ADDRESS_DATA0(NDRSTRUCT):
    structure = (
        ('dynamicKeywordAddress', FW_DYNAMIC_KEYWORD_ADDRESS0),
        ('next', PVOID),
        ('schemaVersion', WORD),
        ('originType', FW_DYNAMIC_KEYWORD_ORIGIN_TYPE),
    )

class FW_DYNAMIC_KEYWORD_ADDRESS_INTERNAL(NDRSTRUCT):
    structure = (
        ('next', PVOID),
        ('schemaVersion', WORD),
        ('id', GUID),
        ('keyword', LPWSTR),
        ('flags', DWORD),
        ('addresses', FW_ADDRESSES),
        ('originType', FW_DYNAMIC_KEYWORD_ORIGIN_TYPE),
    )

class FW_ENFORCEMENT_STATE_ARRAY(NDRUniConformantArray):
    item = FW_ENFORCEMENT_STATE

class PFW_ENFORCEMENT_STATE_ARRAY(NDRPOINTER):
    referent = (
        ('Data', FW_ENFORCEMENT_STATE_ARRAY),
    )

class FW_OBJECT_METADATA(NDRSTRUCT):
    structure = (
        ('qwFilterContextID', ULONGLONG),
        ('dwNumEntries', DWORD),
        ('pEnforcementStates', PFW_ENFORCEMENT_STATE_ARRAY),
    )

class PFW_OBJECT_METADATA(NDRPOINTER):
    referent = (
        ('Data', FW_OBJECT_METADATA),
    )

class FW_OS_PLATFORM(NDRSTRUCT):
    structure = (
        ('bPlatform', BYTE),
        ('bMajorVersion', BYTE),
        ('bMinorVersion', BYTE),
        ('Reserved', BYTE),
    )

class FW_OS_PLATFORM_ARRAY(NDRUniConformantArray):
    item = FW_OS_PLATFORM

class PFW_OS_PLATFORM_ARRAY(NDRPOINTER):
    referent = (
        ('Data', FW_OS_PLATFORM_ARRAY),
    )

class FW_OS_PLATFORM_LIST(NDRSTRUCT):
    structure = (
        ('dwNumEntries', DWORD),
        ('pPlatforms', PFW_OS_PLATFORM_ARRAY),
    )

class LPWSTR_ARRAY(NDRUniConformantArray):
    item = LPWSTR

class PLPWSTR_ARRAY(NDRPOINTER):
    referent = (
        ('Data', LPWSTR_ARRAY),
    )

class FW_NETWORK_NAMES(NDRSTRUCT):
    structure = (
        ('dwNumEntries', DWORD),
        ('wszNames', PLPWSTR_ARRAY),
    )

class FW_PORTS_PAIR(NDRSTRUCT):
    structure = (
        ('LocalPorts', FW_PORTS),
        ('RemotePorts', FW_PORTS),
    )

class FW_EMPTY(NDRSTRUCT):
    structure = (
        ('Data','0s=b""'),
    )

class FW_PORT_OR_ICMP_UNION(NDRUNION):
    union = {
        1  : ('V4TypeCodeList', FW_ICMP_TYPE_CODE_LIST),
        6  : ('Ports', FW_PORTS_PAIR),
        17 : ('Ports', FW_PORTS_PAIR),
        58 : ('V6TypeCodeList', FW_ICMP_TYPE_CODE_LIST),
        'default': ('Empty', FW_EMPTY),
    }

    def __setitem__(self, key, value):
        if key == 'tag':
            if value in self.union:
                self.structure = (self.union[value]),
            elif 'default' in self.union:
                self.structure = (self.union['default']),
            else:
                raise Exception("Unknown tag %d for union!" % value)
            self.__init__(None, isNDR64=self._isNDR64, topLevel=self.topLevel)
            self.fields['tag']['Data'] = value
        else:
            return NDRUNION.__setitem__(self, key, value)

class FW_RULE2_0(NDRSTRUCT):
    structure = (
        ('pNext', PVOID),
        ('wSchemaVersion', WORD),
        ('wszRuleId', LPWSTR),
        ('wszName', LPWSTR),
        ('wszDescription', LPWSTR),
        ('dwProfiles', DWORD),
        ('Direction', FW_DIRECTION),
        ('wIpProtocol', WORD),
        ('ProtocolData', FW_PORT_OR_ICMP_UNION),
        ('LocalAddresses', FW_ADDRESSES),
        ('RemoteAddresses', FW_ADDRESSES),
        ('LocalInterfaceIds', FW_INTERFACE_LUIDS),
        ('dwLocalInterfaceTypes', DWORD),
        ('wszLocalApplication', LPWSTR),
        ('wszLocalService', LPWSTR),
        ('Action', FW_RULE_ACTION),
        ('wFlags', WORD),
        ('wszRemoteMachineAuthorizationList', LPWSTR),
        ('wszRemoteUserAuthorizationList', LPWSTR),
        ('wszEmbeddedContext', LPWSTR),
        ('PlatformValidityList', FW_OS_PLATFORM_LIST),
        ('Status', FW_RULE_STATUS),
        ('Origin', FW_RULE_ORIGIN_TYPE),
        ('wszGPOName', LPWSTR),
        ('Reserved', DWORD),
    )

class PFW_RULE2_0(NDRPOINTER):
    referent = (
        ('Data', FW_RULE2_0),
    )

class FW_RULE2_0_ARRAY(NDRUniConformantArray):
    item = FW_RULE2_0

class PFW_RULE2_0_ARRAY(NDRPOINTER):
    referent = (
        ('Data', FW_RULE2_0_ARRAY),
    )

class FW_RULE2_10(NDRSTRUCT):
    structure = (
        ('pNext', PVOID),
        ('wSchemaVersion', WORD),
        ('wszRuleId', LPWSTR),
        ('wszName', LPWSTR),
        ('wszDescription', LPWSTR),
        ('dwProfiles', DWORD),
        ('Direction', FW_DIRECTION),
        ('wIpProtocol', WORD),
        ('ProtocolData', FW_PORT_OR_ICMP_UNION),
        ('LocalAddresses', FW_ADDRESSES),
        ('RemoteAddresses', FW_ADDRESSES),
        ('LocalInterfaceIds', FW_INTERFACE_LUIDS),
        ('dwLocalInterfaceTypes', DWORD),
        ('wszLocalApplication', LPWSTR),
        ('wszLocalService', LPWSTR),
        ('Action', FW_RULE_ACTION),
        ('wFlags', WORD),
        ('wszRemoteMachineAuthorizationList', LPWSTR),
        ('wszRemoteUserAuthorizationList', LPWSTR),
        ('wszEmbeddedContext', LPWSTR),
        ('PlatformValidityList', FW_OS_PLATFORM_LIST),
        ('Status', FW_RULE_STATUS),
        ('Origin', FW_RULE_ORIGIN_TYPE),
        ('wszGPOName', LPWSTR),
        ('Reserved', DWORD),
        ('pMetaData', PFW_OBJECT_METADATA),
    )

class PFW_RULE2_10(NDRPOINTER):
    referent = (
        ('Data', FW_RULE2_10),
    )

class FW_RULE2_10_ARRAY(NDRUniConformantArray):
    item = FW_RULE2_10

class PFW_RULE2_10_ARRAY(NDRPOINTER):
    referent = (
        ('Data', FW_RULE2_10_ARRAY),
    )

class FW_RULE2_20(NDRSTRUCT):
    structure = (
        ('pNext', PVOID),
        ('wSchemaVersion', WORD),
        ('wszRuleId', LPWSTR),
        ('wszName', LPWSTR),
        ('wszDescription', LPWSTR),
        ('dwProfiles', DWORD),
        ('Direction', FW_DIRECTION),
        ('wIpProtocol', WORD),
        ('ProtocolData', FW_PORT_OR_ICMP_UNION),
        ('LocalAddresses', FW_ADDRESSES),
        ('RemoteAddresses', FW_ADDRESSES),
        ('LocalInterfaceIds', FW_INTERFACE_LUIDS),
        ('dwLocalInterfaceTypes', DWORD),
        ('wszLocalApplication', LPWSTR),
        ('wszLocalService', LPWSTR),
        ('Action', FW_RULE_ACTION),
        ('wFlags', WORD),
        ('wszRemoteMachineAuthorizationList', LPWSTR),
        ('wszRemoteUserAuthorizationList', LPWSTR),
        ('wszEmbeddedContext', LPWSTR),
        ('PlatformValidityList', FW_OS_PLATFORM_LIST),
        ('Status', FW_RULE_STATUS),
        ('Origin', FW_RULE_ORIGIN_TYPE),
        ('wszGPOName', LPWSTR),
        ('Reserved', DWORD),
        ('pMetaData', PFW_OBJECT_METADATA),
        ('wszLocalUserAuthorizationList', LPWSTR),
        ('wszPackageId', LPWSTR),
        ('wszLocalUserOwner', LPWSTR),
        ('dwTrustTupleKeywords', DWORD),
    )

class PFW_RULE2_20(NDRPOINTER):
    referent = (
        ('Data', FW_RULE2_20),
    )

class FW_RULE2_20_ARRAY(NDRUniConformantArray):
    item = FW_RULE2_20

class PFW_RULE2_20_ARRAY(NDRPOINTER):
    referent = (
        ('Data', FW_RULE2_20_ARRAY),
    )

class FW_RULE2_24(NDRSTRUCT):
    structure = (
        ('pNext', PVOID),
        ('wSchemaVersion', WORD),
        ('wszRuleId', LPWSTR),
        ('wszName', LPWSTR),
        ('wszDescription', LPWSTR),
        ('dwProfiles', DWORD),
        ('Direction', FW_DIRECTION),
        ('wIpProtocol', WORD),
        ('ProtocolData', FW_PORT_OR_ICMP_UNION),
        ('LocalAddresses', FW_ADDRESSES),
        ('RemoteAddresses', FW_ADDRESSES),
        ('LocalInterfaceIds', FW_INTERFACE_LUIDS),
        ('dwLocalInterfaceTypes', DWORD),
        ('wszLocalApplication', LPWSTR),
        ('wszLocalService', LPWSTR),
        ('Action', FW_RULE_ACTION),
        ('wFlags', WORD),
        ('wszRemoteMachineAuthorizationList', LPWSTR),
        ('wszRemoteUserAuthorizationList', LPWSTR),
        ('wszEmbeddedContext', LPWSTR),
        ('PlatformValidityList', FW_OS_PLATFORM_LIST),
        ('Status', FW_RULE_STATUS),
        ('Origin', FW_RULE_ORIGIN_TYPE),
        ('wszGPOName', LPWSTR),
        ('Reserved', DWORD),
        ('pMetaData', PFW_OBJECT_METADATA),
        ('wszLocalUserAuthorizationList', LPWSTR),
        ('wszPackageId', LPWSTR),
        ('wszLocalUserOwner', LPWSTR),
        ('dwTrustTupleKeywords', DWORD),
        ('OnNetworkNames', FW_NETWORK_NAMES),
        ('wszSecurityRealmId', LPWSTR),
    )

class PFW_RULE2_24(NDRPOINTER):
    referent = (
        ('Data', FW_RULE2_24),
    )

class FW_RULE2_24_ARRAY(NDRUniConformantArray):
    item = FW_RULE2_24

class PFW_RULE2_24_ARRAY(NDRPOINTER):
    referent = (
        ('Data', FW_RULE2_24_ARRAY),
    )

class FW_RULE2_25(NDRSTRUCT):
    structure = (
        ('pNext', PVOID),
        ('wSchemaVersion', WORD),
        ('wszRuleId', LPWSTR),
        ('wszName', LPWSTR),
        ('wszDescription', LPWSTR),
        ('dwProfiles', DWORD),
        ('Direction', FW_DIRECTION),
        ('wIpProtocol', WORD),
        ('ProtocolData', FW_PORT_OR_ICMP_UNION),
        ('LocalAddresses', FW_ADDRESSES),
        ('RemoteAddresses', FW_ADDRESSES),
        ('LocalInterfaceIds', FW_INTERFACE_LUIDS),
        ('dwLocalInterfaceTypes', DWORD),
        ('wszLocalApplication', LPWSTR),
        ('wszLocalService', LPWSTR),
        ('Action', FW_RULE_ACTION),
        ('wFlags', WORD),
        ('wszRemoteMachineAuthorizationList', LPWSTR),
        ('wszRemoteUserAuthorizationList', LPWSTR),
        ('wszEmbeddedContext', LPWSTR),
        ('PlatformValidityList', FW_OS_PLATFORM_LIST),
        ('Status', FW_RULE_STATUS),
        ('Origin', FW_RULE_ORIGIN_TYPE),
        ('wszGPOName', LPWSTR),
        ('Reserved', DWORD),
        ('pMetaData', PFW_OBJECT_METADATA),
        ('wszLocalUserAuthorizationList', LPWSTR),
        ('wszPackageId', LPWSTR),
        ('wszLocalUserOwner', LPWSTR),
        ('dwTrustTupleKeywords', DWORD),
        ('OnNetworkNames', FW_NETWORK_NAMES),
        ('wszSecurityRealmId', LPWSTR),
        ('wFlags2', WORD),
    )

class PFW_RULE2_25(NDRPOINTER):
    referent = (
        ('Data', FW_RULE2_25),
    )

class FW_RULE2_25_ARRAY(NDRUniConformantArray):
    item = FW_RULE2_25

class PFW_RULE2_25_ARRAY(NDRPOINTER):
    referent = (
        ('Data', FW_RULE2_25_ARRAY),
    )

class FW_RULE2_26(NDRSTRUCT):
    structure = (
        ('pNext', PVOID),
        ('wSchemaVersion', WORD),
        ('wszRuleId', LPWSTR),
        ('wszName', LPWSTR),
        ('wszDescription', LPWSTR),
        ('dwProfiles', DWORD),
        ('Direction', FW_DIRECTION),
        ('wIpProtocol', WORD),
        ('ProtocolData', FW_PORT_OR_ICMP_UNION),
        ('LocalAddresses', FW_ADDRESSES),
        ('RemoteAddresses', FW_ADDRESSES),
        ('LocalInterfaceIds', FW_INTERFACE_LUIDS),
        ('dwLocalInterfaceTypes', DWORD),
        ('wszLocalApplication', LPWSTR),
        ('wszLocalService', LPWSTR),
        ('Action', FW_RULE_ACTION),
        ('wFlags', WORD),
        ('wszRemoteMachineAuthorizationList', LPWSTR),
        ('wszRemoteUserAuthorizationList', LPWSTR),
        ('wszEmbeddedContext', LPWSTR),
        ('PlatformValidityList', FW_OS_PLATFORM_LIST),
        ('Status', FW_RULE_STATUS),
        ('Origin', FW_RULE_ORIGIN_TYPE),
        ('wszGPOName', LPWSTR),
        ('Reserved', DWORD),
        ('pMetaData', PFW_OBJECT_METADATA),
        ('wszLocalUserAuthorizationList', LPWSTR),
        ('wszPackageId', LPWSTR),
        ('wszLocalUserOwner', LPWSTR),
        ('dwTrustTupleKeywords', DWORD),
        ('OnNetworkNames', FW_NETWORK_NAMES),
        ('wszSecurityRealmId', LPWSTR),
        ('wFlags2', WORD),
        ('RemoteOutServerNames', FW_NETWORK_NAMES),
    )

class PFW_RULE2_26(NDRPOINTER):
    referent = (
        ('Data', FW_RULE2_26),
    )

class FW_RULE2_26_ARRAY(NDRUniConformantArray):
    item = FW_RULE2_26

class PFW_RULE2_26_ARRAY(NDRPOINTER):
    referent = (
        ('Data', FW_RULE2_26_ARRAY),
    )

class FW_RULE2_27(NDRSTRUCT):
    structure = (
        ('pNext', PVOID),
        ('wSchemaVersion', WORD),
        ('wszRuleId', LPWSTR),
        ('wszName', LPWSTR),
        ('wszDescription', LPWSTR),
        ('dwProfiles', DWORD),
        ('Direction', FW_DIRECTION),
        ('wIpProtocol', WORD),
        ('ProtocolData', FW_PORT_OR_ICMP_UNION),
        ('LocalAddresses', FW_ADDRESSES),
        ('RemoteAddresses', FW_ADDRESSES),
        ('LocalInterfaceIds', FW_INTERFACE_LUIDS),
        ('dwLocalInterfaceTypes', DWORD),
        ('wszLocalApplication', LPWSTR),
        ('wszLocalService', LPWSTR),
        ('Action', FW_RULE_ACTION),
        ('wFlags', WORD),
        ('wszRemoteMachineAuthorizationList', LPWSTR),
        ('wszRemoteUserAuthorizationList', LPWSTR),
        ('wszEmbeddedContext', LPWSTR),
        ('PlatformValidityList', FW_OS_PLATFORM_LIST),
        ('Status', FW_RULE_STATUS),
        ('Origin', FW_RULE_ORIGIN_TYPE),
        ('wszGPOName', LPWSTR),
        ('Reserved', DWORD),
        ('pMetaData', PFW_OBJECT_METADATA),
        ('wszLocalUserAuthorizationList', LPWSTR),
        ('wszPackageId', LPWSTR),
        ('wszLocalUserOwner', LPWSTR),
        ('dwTrustTupleKeywords', DWORD),
        ('OnNetworkNames', FW_NETWORK_NAMES),
        ('wszSecurityRealmId', LPWSTR),
        ('wFlags2', WORD),
        ('RemoteOutServerNames', FW_NETWORK_NAMES),
        ('wszFqbn', LPWSTR),
        ('compartmentId', DWORD),
    )

class PFW_RULE2_27(NDRPOINTER):
    referent = (
        ('Data', FW_RULE2_27),
    )

class FW_RULE2_27_ARRAY(NDRUniConformantArray):
    item = FW_RULE2_27

class PFW_RULE2_27_ARRAY(NDRPOINTER):
    referent = (
        ('Data', FW_RULE2_27_ARRAY),
    )

class FW_RULE2_31(NDRSTRUCT):
    structure = (
        ('pNext', PVOID),
        ('wSchemaVersion', WORD),
        ('wszRuleId', LPWSTR),
        ('wszName', LPWSTR),
        ('wszDescription', LPWSTR),
        ('dwProfiles', DWORD),
        ('Direction', FW_DIRECTION),
        ('wIpProtocol', WORD),
        ('ProtocolData', FW_PORT_OR_ICMP_UNION),
        ('LocalAddresses', FW_ADDRESSES),
        ('RemoteAddresses', FW_ADDRESSES),
        ('LocalInterfaceIds', FW_INTERFACE_LUIDS),
        ('dwLocalInterfaceTypes', DWORD),
        ('wszLocalApplication', LPWSTR),
        ('wszLocalService', LPWSTR),
        ('Action', FW_RULE_ACTION),
        ('wFlags', WORD),
        ('wszRemoteMachineAuthorizationList', LPWSTR),
        ('wszRemoteUserAuthorizationList', LPWSTR),
        ('wszEmbeddedContext', LPWSTR),
        ('PlatformValidityList', FW_OS_PLATFORM_LIST),
        ('Status', FW_RULE_STATUS),
        ('Origin', FW_RULE_ORIGIN_TYPE),
        ('wszGPOName', LPWSTR),
        ('Reserved', DWORD),
        ('pMetaData', PFW_OBJECT_METADATA),
        ('wszLocalUserAuthorizationList', LPWSTR),
        ('wszPackageId', LPWSTR),
        ('wszLocalUserOwner', LPWSTR),
        ('dwTrustTupleKeywords', DWORD),
        ('OnNetworkNames', FW_NETWORK_NAMES),
        ('wszSecurityRealmId', LPWSTR),
        ('wFlags2', WORD),
        ('RemoteOutServerNames', FW_NETWORK_NAMES),
        ('wszFqbn', LPWSTR),
        ('compartmentId', DWORD),
        ('providerContextKey', GUID),
        ('RemoteDynamicKeywordAddresses', FW_DYNAMIC_KEYWORD_ADDRESS_ID_LIST),
    )

class PFW_RULE2_31(NDRPOINTER):
    referent = (
        ('Data', FW_RULE2_31),
    )

class FW_RULE2_31_ARRAY(NDRUniConformantArray):
    item = FW_RULE2_31

class PFW_RULE2_31_ARRAY(NDRPOINTER):
    referent = (
        ('Data', FW_RULE2_31_ARRAY),
    )

class FW_RULE(NDRSTRUCT):
    structure = (
        ('pNext', PVOID),
        ('wSchemaVersion', WORD),
        ('wszRuleId', LPWSTR),
        ('wszName', LPWSTR),
        ('wszDescription', LPWSTR),
        ('dwProfiles', DWORD),
        ('Direction', FW_DIRECTION),
        ('wIpProtocol', WORD),
        ('ProtocolData', FW_PORT_OR_ICMP_UNION),
        ('LocalAddresses', FW_ADDRESSES),
        ('RemoteAddresses', FW_ADDRESSES),
        ('LocalInterfaceIds', FW_INTERFACE_LUIDS),
        ('dwLocalInterfaceTypes', DWORD),
        ('wszLocalApplication', LPWSTR),
        ('wszLocalService', LPWSTR),
        ('Action', FW_RULE_ACTION),
        ('wFlags', WORD),
        ('wszRemoteMachineAuthorizationList', LPWSTR),
        ('wszRemoteUserAuthorizationList', LPWSTR),
        ('wszEmbeddedContext', LPWSTR),
        ('PlatformValidityList', FW_OS_PLATFORM_LIST),
        ('Status', FW_RULE_STATUS),
        ('Origin', FW_RULE_ORIGIN_TYPE),
        ('wszGPOName', LPWSTR),
        ('Reserved', DWORD),
        ('pMetaData', PFW_OBJECT_METADATA),
        ('wszLocalUserAuthorizationList', LPWSTR),
        ('wszPackageId', LPWSTR),
        ('wszLocalUserOwner', LPWSTR),
        ('dwTrustTupleKeywords', DWORD),
        ('OnNetworkNames', FW_NETWORK_NAMES),
        ('wszSecurityRealmId', LPWSTR),
        ('wFlags2', WORD),
        ('RemoteOutServerNames', FW_NETWORK_NAMES),
        ('wszFqbn', LPWSTR),
        ('compartmentId', DWORD),
        ('providerContextKey', GUID),
        ('RemoteDynamicKeywordAddresses', FW_DYNAMIC_KEYWORD_ADDRESS_ID_LIST),
        ('wszPackageFamilyName', LPWSTR),
    )

class PFW_RULE(NDRPOINTER):
    referent = (
        ('Data', FW_RULE),
    )

class FW_RULE_ARRAY(NDRUniConformantArray):
    item = FW_RULE

class PFW_RULE_ARRAY(NDRPOINTER):
    referent = (
        ('Data', FW_RULE_ARRAY),
    )

class FW_NETWORK(NDRSTRUCT):
    structure = (
        ('pszName', LPWSTR),
        ('ProfileType', FW_PROFILE_TYPE),
    )

class FW_NETWORK_ARRAY(NDRUniConformantArray):
    item = FW_NETWORK

class PFW_NETWORK_ARRAY(NDRPOINTER):
    referent = (
        ('Data', FW_NETWORK_ARRAY),
    )

class FW_ADAPTER(NDRSTRUCT):
    structure = (
        ('pszFriendlyName', LPWSTR),
        ('Guid', GUID),
    )

class FW_ADAPTER_ARRAY(NDRUniConformantArray):
    item = FW_ADAPTER

class PFW_ADAPTER_ARRAY(NDRPOINTER):
    referent = (
        ('Data', FW_ADAPTER_ARRAY),
    )

class FW_DIAG_APP(NDRSTRUCT):
    structure = (
        ('pszAppPath', LPWSTR),
    )

class FW_RULE_CATEGORY_ARRAY(NDRUniConformantArray):
    item = FW_RULE_CATEGORY

class PFW_RULE_CATEGORY_ARRAY(NDRPOINTER):
    referent = (
        ('Data', FW_RULE_CATEGORY_ARRAY),
    )

class FW_PRODUCT(NDRSTRUCT):
    structure = (
        ('dwFlags', DWORD),
        ('dwNumRuleCategories', DWORD),
        ('pRuleCategories', PFW_RULE_CATEGORY_ARRAY),
        ('pszDisplayName', LPWSTR),
        ('pszPathToSignedProductExe', LPWSTR),
    )

class FW_PRODUCT_ARRAY(NDRUniConformantArray):
    item = FW_PRODUCT

class PFW_PRODUCT_ARRAY(NDRPOINTER):
    referent = (
        ('Data', FW_PRODUCT_ARRAY),
    )

class FW_CS_RULE2_0(NDRSTRUCT):
    structure = (
        ('pNext', PVOID),
        ('wSchemaVersion', WORD),
        ('wszRuleId', LPWSTR),
        ('wszName', LPWSTR),
        ('wszDescription', LPWSTR),
        ('dwProfiles', DWORD),
        ('Endpoint1', FW_ADDRESSES),
        ('Endpoint2', FW_ADDRESSES),
        ('LocalInterfaceIds', FW_INTERFACE_LUIDS),
        ('dwLocalInterfaceTypes', DWORD),
        ('dwLocalTunnelEndpointV4', DWORD),
        ('LocalTunnelEndpointV6','16s=b"\\x00"*16'),
        ('dwRemoteTunnelEndpointV4', DWORD),
        ('RemoteTunnelEndpointV6','16s=b"\\x00"*16'),
        ('Endpoint1Ports', FW_PORTS),
        ('Endpoint2Ports', FW_PORTS),
        ('wIpProtocol', WORD),
        ('wszPhase1AuthSet', LPWSTR),
        ('wszPhase2CryptoSet', LPWSTR),
        ('wszPhase2AuthSet', LPWSTR),
        ('Action', FW_CS_RULE_ACTION),
        ('wFlags', WORD),
        ('wszEmbeddedContext', LPWSTR),
        ('PlatformValidityList', FW_OS_PLATFORM_LIST),
        ('Origin', FW_RULE_ORIGIN_TYPE),
        ('wszGPOName', LPWSTR),
        ('Status', FW_RULE_STATUS),
    )

class PFW_CS_RULE2_0(NDRPOINTER):
    referent = (
        ('Data', FW_CS_RULE2_0),
    )

class FW_CS_RULE2_0_ARRAY(NDRUniConformantArray):
    item = FW_CS_RULE2_0

class PFW_CS_RULE2_0_ARRAY(NDRPOINTER):
    referent = (
        ('Data', FW_CS_RULE2_0_ARRAY),
    )

class FW_CS_RULE2_10(NDRSTRUCT):
    structure = (
        ('pNext', PVOID),
        ('wSchemaVersion', WORD),
        ('wszRuleId', LPWSTR),
        ('wszName', LPWSTR),
        ('wszDescription', LPWSTR),
        ('dwProfiles', DWORD),
        ('Endpoint1', FW_ADDRESSES),
        ('Endpoint2', FW_ADDRESSES),
        ('LocalInterfaceIds', FW_INTERFACE_LUIDS),
        ('dwLocalInterfaceTypes', DWORD),
        ('dwLocalTunnelEndpointV4', DWORD),
        ('LocalTunnelEndpointV6','16s=b"\\x00"*16'),
        ('dwRemoteTunnelEndpointV4', DWORD),
        ('RemoteTunnelEndpointV6','16s=b"\\x00"*16'),
        ('Endpoint1Ports', FW_PORTS),
        ('Endpoint2Ports', FW_PORTS),
        ('wIpProtocol', WORD),
        ('wszPhase1AuthSet', LPWSTR),
        ('wszPhase2CryptoSet', LPWSTR),
        ('wszPhase2AuthSet', LPWSTR),
        ('Action', FW_CS_RULE_ACTION),
        ('wFlags', WORD),
        ('wszEmbeddedContext', LPWSTR),
        ('PlatformValidityList', FW_OS_PLATFORM_LIST),
        ('Origin', FW_RULE_ORIGIN_TYPE),
        ('wszGPOName', LPWSTR),
        ('Status', FW_RULE_STATUS),
        ('wszMMParentRuleId', LPWSTR),
        ('Reserved', DWORD),
        ('pMetaData', PFW_OBJECT_METADATA),
    )

class PFW_CS_RULE2_10(NDRPOINTER):
    referent = (
        ('Data', FW_CS_RULE2_10),
    )

class FW_CS_RULE2_10_ARRAY(NDRUniConformantArray):
    item = FW_CS_RULE2_10

class PFW_CS_RULE2_10_ARRAY(NDRPOINTER):
    referent = (
        ('Data', FW_CS_RULE2_10_ARRAY),
    )

class FW_CS_RULE(NDRSTRUCT):
    structure = (
        ('pNext', PVOID),
        ('wSchemaVersion', WORD),
        ('wszRuleId', LPWSTR),
        ('wszName', LPWSTR),
        ('wszDescription', LPWSTR),
        ('dwProfiles', DWORD),
        ('Endpoint1', FW_ADDRESSES),
        ('Endpoint2', FW_ADDRESSES),
        ('LocalInterfaceIds', FW_INTERFACE_LUIDS),
        ('dwLocalInterfaceTypes', DWORD),
        ('dwLocalTunnelEndpointV4', DWORD),
        ('LocalTunnelEndpointV6','16s=b"\\x00"*16'),
        ('dwRemoteTunnelEndpointV4', DWORD),
        ('RemoteTunnelEndpointV6','16s=b"\\x00"*16'),
        ('Endpoint1Ports', FW_PORTS),
        ('Endpoint2Ports', FW_PORTS),
        ('wIpProtocol', WORD),
        ('wszPhase1AuthSet', LPWSTR),
        ('wszPhase2CryptoSet', LPWSTR),
        ('wszPhase2AuthSet', LPWSTR),
        ('Action', FW_CS_RULE_ACTION),
        ('wFlags', WORD),
        ('wszEmbeddedContext', LPWSTR),
        ('PlatformValidityList', FW_OS_PLATFORM_LIST),
        ('Origin', FW_RULE_ORIGIN_TYPE),
        ('wszGPOName', LPWSTR),
        ('Status', FW_RULE_STATUS),
        ('wszMMParentRuleId', LPWSTR),
        ('Reserved', DWORD),
        ('pMetaData', PFW_OBJECT_METADATA),
        ('wszRemoteTunnelEndpointFqdn', LPWSTR),
        ('RemoteTunnelEndpoints', FW_ADDRESSES),
        ('dwKeyModules', DWORD),
        ('FwdPathSALifetime', DWORD),
        ('wszTransportMachineAuthzSDDL', LPWSTR),
        ('wszTransportUserAuthzSDDL', LPWSTR),
    )

class PFW_CS_RULE(NDRPOINTER):
    referent = (
        ('Data', FW_CS_RULE),
    )

class FW_CS_RULE_ARRAY(NDRUniConformantArray):
    item = FW_CS_RULE

class PFW_CS_RULE_ARRAY(NDRPOINTER):
    referent = (
        ('Data', FW_CS_RULE_ARRAY),
    )

class FW_AUTH_SUITE2_10_CERT(NDRSTRUCT):
    structure = (
        ('wszCAName', LPWSTR),
    )

class FW_AUTH_SUITE2_10_SHKEY(NDRSTRUCT):
    structure = (
        ('wszSHKey', LPWSTR),
    )

class FW_AUTH_SUITE2_10_UNION(NDRUNION):
    commonHdr = (
        ('tag', DWORD),
    )
    union = {
        3 : ('SharedKey', FW_AUTH_SUITE2_10_SHKEY),
        5 : ('Cert', FW_AUTH_SUITE2_10_CERT),
        7 : ('Cert', FW_AUTH_SUITE2_10_CERT),
    }

class FW_AUTH_SUITE2_10(NDRSTRUCT):
    structure = (
        ('Method', FW_AUTH_METHOD),
        ('wFlags', WORD),
        ('AuthSuite', FW_AUTH_SUITE2_10_UNION),
    )

class FW_CERT_CRITERIA(NDRSTRUCT):
    structure = (
        ('wSchemaVersion', WORD),
        ('wFlags', WORD),
        ('CertCriteriaType', FW_CERT_CRITERIA_TYPE),
        ('NameType', FW_CERT_CRITERIA_NAME_TYPE),
        ('wszName', LPWSTR),
        ('dwNumEku', DWORD),
        ('ppEku', LPSTR),
        ('wszHash', LPWSTR),
    )

class PFW_CERT_CRITERIA(NDRPOINTER):
    referent = (
        ('Data', FW_CERT_CRITERIA),
    )

class FW_AUTH_SUITE_CERT(NDRSTRUCT):
    structure = (
        ('wszCAName', LPWSTR),
        ('pCertCriteria', PFW_CERT_CRITERIA),
    )

class FW_AUTH_SUITE_SHKEY(NDRSTRUCT):
    structure = (
        ('wszSHKey', LPWSTR),
    )

class FW_AUTH_SUITE_PROXY(NDRSTRUCT):
    structure = (
        ('wszProxyServer', LPWSTR),
    )

class FW_AUTH_SUITE_UNION(NDRUNION):
    commonHdr = (
        ('tag', DWORD),
    )
    union = {
        2 : ('ProxyServer', FW_AUTH_SUITE_PROXY),
        3 : ('SharedKey', FW_AUTH_SUITE_SHKEY),
        5 : ('Cert', FW_AUTH_SUITE_CERT),
        6 : ('ProxyServer', FW_AUTH_SUITE_PROXY),
        7 : ('Cert', FW_AUTH_SUITE_CERT),
    }

class FW_AUTH_SUITE(NDRSTRUCT):
    structure = (
        ('Method', FW_AUTH_METHOD),
        ('wFlags', WORD),
        ('AuthSuite', FW_AUTH_SUITE_UNION),
    )

class FW_AUTH_SUITE2_10_ARRAY(NDRUniConformantArray):
    item = FW_AUTH_SUITE2_10

class PFW_AUTH_SUITE2_10_ARRAY(NDRPOINTER):
    referent = (
        ('Data', FW_AUTH_SUITE2_10_ARRAY),
    )

class FW_AUTH_SET2_10(NDRSTRUCT):
    structure = (
        ('pNext', PVOID),
        ('wSchemaVersion', WORD),
        ('IpSecPhase', FW_IPSEC_PHASE),
        ('wszSetId', LPWSTR),
        ('wszName', LPWSTR),
        ('wszDescription', LPWSTR),
        ('wszEmbeddedContext', LPWSTR),
        ('dwNumSuites', DWORD),
        ('pSuites', PFW_AUTH_SUITE2_10_ARRAY),
        ('Origin', FW_RULE_ORIGIN_TYPE),
        ('wszGPOName', LPWSTR),
        ('Status', FW_RULE_STATUS),
        ('dwAuthSetFlags', DWORD),
    )

class PFW_AUTH_SET2_10(NDRPOINTER):
    referent = (
        ('Data', FW_AUTH_SET2_10),
    )

class FW_AUTH_SET2_10_ARRAY(NDRUniConformantArray):
    item = FW_AUTH_SET2_10

class PFW_AUTH_SET2_10_ARRAY(NDRPOINTER):
    referent = (
        ('Data', FW_AUTH_SET2_10_ARRAY),
    )

class FW_AUTH_SUITE_ARRAY(NDRUniConformantArray):
    item = FW_AUTH_SUITE

class PFW_AUTH_SUITE_ARRAY(NDRPOINTER):
    referent = (
        ('Data', FW_AUTH_SUITE_ARRAY),
    )

class FW_AUTH_SET(NDRSTRUCT):
    structure = (
        ('pNext', PVOID),
        ('wSchemaVersion', WORD),
        ('IpSecPhase', FW_IPSEC_PHASE),
        ('wszSetId', LPWSTR),
        ('wszName', LPWSTR),
        ('wszDescription', LPWSTR),
        ('wszEmbeddedContext', LPWSTR),
        ('dwNumSuites', DWORD),
        ('pSuites', PFW_AUTH_SUITE_ARRAY),
        ('Origin', FW_RULE_ORIGIN_TYPE),
        ('wszGPOName', LPWSTR),
        ('Status', FW_RULE_STATUS),
        ('dwAuthSetFlags', DWORD),
    )

class PFW_AUTH_SET(NDRPOINTER):
    referent = (
        ('Data', FW_AUTH_SET),
    )

class FW_AUTH_SET_ARRAY(NDRUniConformantArray):
    item = FW_AUTH_SET

class PFW_AUTH_SET_ARRAY(NDRPOINTER):
    referent = (
        ('Data', FW_AUTH_SET_ARRAY),
    )

class FW_PHASE1_CRYPTO_SUITE(NDRSTRUCT):
    structure = (
        ('KeyExchange', FW_CRYPTO_KEY_EXCHANGE_TYPE),
        ('Encryption', FW_CRYPTO_ENCRYPTION_TYPE),
        ('Hash', FW_CRYPTO_HASH_TYPE),
        ('dwP1CryptoSuiteFlags', DWORD),
    )

class FW_PHASE2_CRYPTO_SUITE(NDRSTRUCT):
    structure = (
        ('Protocol', FW_CRYPTO_PROTOCOL_TYPE),
        ('AhHash', FW_CRYPTO_HASH_TYPE),
        ('EspHash', FW_CRYPTO_HASH_TYPE),
        ('Encryption', FW_CRYPTO_ENCRYPTION_TYPE),
        ('dwTimeoutMinutes', DWORD),
        ('dwTimeoutKBytes', DWORD),
        ('dwP2CryptoSuiteFlags', DWORD),
    )

class FW_PHASE1_CRYPTO_SUITE_ARRAY(NDRUniConformantArray):
    item = FW_PHASE1_CRYPTO_SUITE

class PFW_PHASE1_CRYPTO_SUITE_ARRAY(NDRPOINTER):
    referent = (
        ('Data', FW_PHASE1_CRYPTO_SUITE_ARRAY),
    )

class FW_PHASE2_CRYPTO_SUITE_ARRAY(NDRUniConformantArray):
    item = FW_PHASE2_CRYPTO_SUITE

class PFW_PHASE2_CRYPTO_SUITE_ARRAY(NDRPOINTER):
    referent = (
        ('Data', FW_PHASE2_CRYPTO_SUITE_ARRAY),
    )

class FW_CRYPTO_SET_PHASE1(NDRSTRUCT):
    structure = (
        ('wFlags', WORD),
        ('dwNumPhase1Suites', DWORD),
        ('pPhase1Suites', PFW_PHASE1_CRYPTO_SUITE_ARRAY),
        ('dwTimeOutMinutes', DWORD),
        ('dwTimeOutSessions', DWORD),
    )

class FW_CRYPTO_SET_PHASE2(NDRSTRUCT):
    structure = (
        ('Pfs', FW_PHASE2_CRYPTO_PFS),
        ('dwNumPhase2Suites', DWORD),
        ('pPhase2Suites', PFW_PHASE2_CRYPTO_SUITE_ARRAY),
    )

class FW_CRYPTO_SET_UNION(NDRUNION):
    commonHdr = (
        ('tag', DWORD),
    )
    union = {
        1 : ('Phase1', FW_CRYPTO_SET_PHASE1),
        2 : ('Phase2', FW_CRYPTO_SET_PHASE2),
    }

class FW_CRYPTO_SET(NDRSTRUCT):
    structure = (
        ('pNext', PVOID),
        ('wSchemaVersion', WORD),
        ('IpSecPhase', FW_IPSEC_PHASE),
        ('wszSetId', LPWSTR),
        ('wszName', LPWSTR),
        ('wszDescription', LPWSTR),
        ('wszEmbeddedContext', LPWSTR),
        ('CryptoSet', FW_CRYPTO_SET_UNION),
        ('Origin', FW_RULE_ORIGIN_TYPE),
        ('wszGPOName', LPWSTR),
        ('Status', FW_RULE_STATUS),
        ('dwCryptoSetFlags', DWORD),
    )

class PFW_CRYPTO_SET(NDRPOINTER):
    referent = (
        ('Data', FW_CRYPTO_SET),
    )

class FW_CRYPTO_SET_ARRAY(NDRUniConformantArray):
    item = FW_CRYPTO_SET

class PFW_CRYPTO_SET_ARRAY(NDRPOINTER):
    referent = (
        ('Data', FW_CRYPTO_SET_ARRAY),
    )

class FW_BYTE_BLOB(NDRSTRUCT):
    structure = (
        ('dwSize', DWORD),
        ('Blob', PBYTE_ARRAY),
    )

class FW_COOKIE_PAIR(NDRSTRUCT):
    structure = (
        ('Initiator', ULONGLONG),
        ('Responder', ULONGLONG),
    )

class FW_CERT_INFO(NDRSTRUCT):
    structure = (
        ('SubjectName', FW_BYTE_BLOB),
        ('dwCertFlags', DWORD),
    )

class FW_AUTH_INFO_CERT(NDRSTRUCT):
    structure = (
        ('MyCert', FW_CERT_INFO),
        ('PeerCert', FW_CERT_INFO),
    )

class FW_AUTH_INFO_KERB(NDRSTRUCT):
    structure = (
        ('wszMyId', LPWSTR),
        ('wszPeerId', LPWSTR),
    )

class FW_AUTH_INFO_UNION(NDRUNION):
    commonHdr = (
        ('tag', DWORD),
    )
    union = {
        2  : ('Kerberos', FW_AUTH_INFO_KERB),
        5  : ('Cert', FW_AUTH_INFO_CERT),
        6  : ('Kerberos', FW_AUTH_INFO_KERB),
        7  : ('Cert', FW_AUTH_INFO_CERT),
        9  : ('Kerberos', FW_AUTH_INFO_KERB),
        10 : ('Kerberos', FW_AUTH_INFO_KERB),
    }

class FW_AUTH_INFO(NDRSTRUCT):
    structure = (
        ('AuthMethod', FW_AUTH_METHOD),
        ('AuthInfo', FW_AUTH_INFO_UNION),
        ('dwAuthInfoFlags', DWORD),
    )

class PFW_AUTH_INFO(NDRPOINTER):
    referent = (
        ('Data', FW_AUTH_INFO),
    )

class FW_ENDPOINTS(NDRSTRUCT):
    structure = (
        ('IpVersion', FW_IP_VERSION),
        ('dwSourceV4Address', DWORD),
        ('dwDestinationV4Address', DWORD),
        ('SourceV6Address','16s=b"\\x00"*16'),
        ('DestinationV6Address','16s=b"\\x00"*16'),
    )

class PFW_ENDPOINTS(NDRPOINTER):
    referent = (
        ('Data', FW_ENDPOINTS),
    )

class FW_PHASE1_SA_DETAILS(NDRSTRUCT):
    structure = (
        ('SaId', ULONGLONG),
        ('KeyModuleType', FW_PHASE1_KEY_MODULE_TYPE),
        ('Endpoints', FW_ENDPOINTS),
        ('SelectedProposal', FW_PHASE1_CRYPTO_SUITE),
        ('dwProposalLifetimeKBytes', DWORD),
        ('dwProposalLifetimeMinutes', DWORD),
        ('dwProposalMaxNumPhase2', DWORD),
        ('CookiePair', FW_COOKIE_PAIR),
        ('pFirstAuth', PFW_AUTH_INFO),
        ('pSecondAuth', PFW_AUTH_INFO),
        ('dwP1SaFlags', DWORD),
    )

class FW_PHASE1_SA_DETAILS_ARRAY(NDRUniConformantArray):
    item = FW_PHASE1_SA_DETAILS

class PFW_PHASE1_SA_DETAILS_ARRAY(NDRPOINTER):
    referent = (
        ('Data', FW_PHASE1_SA_DETAILS_ARRAY),
    )

class FW_PHASE2_SA_DETAILS(NDRSTRUCT):
    structure = (
        ('SaId', ULONGLONG),
        ('Direction', FW_DIRECTION),
        ('Endpoints', FW_ENDPOINTS),
        ('wLocalPort', WORD),
        ('wRemotePort', WORD),
        ('wIpProtocol', WORD),
        ('SelectedProposal', FW_PHASE2_CRYPTO_SUITE),
        ('Pfs', FW_PHASE2_CRYPTO_PFS),
        ('TransportFilterId', GUID),
        ('dwP2SaFlags', DWORD),
    )

class FW_PHASE2_SA_DETAILS_ARRAY(NDRUniConformantArray):
    item = FW_PHASE2_SA_DETAILS

class PFW_PHASE2_SA_DETAILS_ARRAY(NDRPOINTER):
    referent = (
        ('Data', FW_PHASE2_SA_DETAILS_ARRAY),
    )

class FW_MM_RULE(NDRSTRUCT):
    structure = (
        ('pNext', PVOID),
        ('wSchemaVersion', WORD),
        ('wszRuleId', LPWSTR),
        ('wszName', LPWSTR),
        ('wszDescription', LPWSTR),
        ('dwProfiles', DWORD),
        ('Endpoint1', FW_ADDRESSES),
        ('Endpoint2', FW_ADDRESSES),
        ('wszPhase1AuthSet', LPWSTR),
        ('wszPhase1CryptoSet', LPWSTR),
        ('wFlags', WORD),
        ('wszEmbeddedContext', LPWSTR),
        ('PlatformValidityList', FW_OS_PLATFORM_LIST),
        ('Origin', FW_RULE_ORIGIN_TYPE),
        ('wszGPOName', LPWSTR),
        ('Status', FW_RULE_STATUS),
        ('Reserved', DWORD),
        ('pMetaData', PFW_OBJECT_METADATA),
    )

class PFW_MM_RULE(NDRPOINTER):
    referent = (
        ('Data', FW_MM_RULE),
    )

class FW_MM_RULE_ARRAY(NDRUniConformantArray):
    item = FW_MM_RULE

class PFW_MM_RULE_ARRAY(NDRPOINTER):
    referent = (
        ('Data', FW_MM_RULE_ARRAY),
    )

class FW_MATCH_VALUE(NDRUNION):
    commonHdr = (
        ('type', FW_DATA_TYPE),
    )
    commonHdr64 = (
        ('type', FW_DATA_TYPE),
    )
    union = {
        FW_DATA_TYPE.FW_DATA_TYPE_UINT8          : ('uInt8', BYTE),
        FW_DATA_TYPE.FW_DATA_TYPE_UINT16         : ('uInt16', WORD),
        FW_DATA_TYPE.FW_DATA_TYPE_UINT32         : ('uInt32', DWORD),
        FW_DATA_TYPE.FW_DATA_TYPE_UINT64         : ('uInt64', ULONGLONG),
        FW_DATA_TYPE.FW_DATA_TYPE_UNICODE_STRING : ('wszString', LPWSTR),
        FW_DATA_TYPE.FW_DATA_TYPE_EMPTY          : ('Empty', FW_EMPTY),
    }

    def __setitem__(self, key, value):
        if key == 'type':
            if value in self.union:
                self.structure = (self.union[value]),
                self.__init__(None, isNDR64=self._isNDR64, topLevel=self.topLevel)
                self.fields['type']['Data'] = value
            else:
                raise Exception("Unknown tag %d for union!" % value)
        else:
            return NDRUNION.__setitem__(self, key, value)

class FW_QUERY_CONDITION(NDRSTRUCT):
    structure = (
        ('matchKey', FW_MATCH_KEY),
        ('matchType', FW_MATCH_TYPE),
        ('matchValue', FW_MATCH_VALUE),
    )

class FW_QUERY_CONDITION_ARRAY(NDRUniConformantArray):
    item = FW_QUERY_CONDITION

class PFW_QUERY_CONDITION_ARRAY(NDRPOINTER):
    referent = (
        ('Data', FW_QUERY_CONDITION_ARRAY),
    )

class FW_QUERY_CONDITIONS(NDRSTRUCT):
    structure = (
        ('dwNumEntries', DWORD),
        ('AndedConditions', PFW_QUERY_CONDITION_ARRAY),
    )

class FW_QUERY_CONDITIONS_ARRAY(NDRUniConformantArray):
    item = FW_QUERY_CONDITIONS

class PFW_QUERY_CONDITIONS_ARRAY(NDRPOINTER):
    referent = (
        ('Data', FW_QUERY_CONDITIONS_ARRAY),
    )

class FW_QUERY(NDRSTRUCT):
    structure = (
        ('wSchemaVersion', WORD),
        ('dwNumEntries', DWORD),
        ('ORConditions', PFW_QUERY_CONDITIONS_ARRAY),
        ('Status', FW_RULE_STATUS),
    )

class PFW_QUERY(NDRPOINTER):
    referent = (
        ('Data', FW_QUERY),
    )

class FW_HYPERV_VM_CREATOR0(NDRSTRUCT):
    structure = (
        ('next', PVOID),
        ('schemaVersion', WORD),
        ('id', GUID),
        ('friendlyName', LPWSTR),
    )

class FW_HYPERV_PORT0(NDRSTRUCT):
    structure = (
        ('next', PVOID),
        ('switchName', LPWSTR),
        ('portName', LPWSTR),
        ('vmCreatorId', GUID),
        ('interfaceGuid', GUID),
        ('partitionGuid', GUID),
        ('flags', DWORD),
    )

class FW_HYPERV_PORT1(NDRSTRUCT):
    structure = (
        ('next', PVOID),
        ('switchName', LPWSTR),
        ('portName', LPWSTR),
        ('vmCreatorId', GUID),
        ('interfaceGuid', GUID),
        ('partitionGuid', GUID),
        ('flags', DWORD),
        ('profileType', FW_PROFILE_TYPE),
        ('networkType', FW_HYPERV_NETWORK_TYPE),
        ('constrainedInterfaceAlias', LPWSTR),
    )

class FW_HYPERV_VM_CONFIG_VALUE0(NDRSTRUCT):
    structure = (
        ('pdwVal', LPDWORD),
    )

class FW_HYPERV_RULE_METADATA(NDRSTRUCT):
    structure = (
        ('switchName', LPWSTR),
        ('portName', LPWSTR),
        ('enforcementState', FW_HYPERV_RULE_PORT_ENFORCEMENT_STATE),
    )

class FW_HYPERV_RULE_METADATA_ARRAY(NDRUniConformantArray):
    item = FW_HYPERV_RULE_METADATA

class PFW_HYPERV_RULE_METADATA_ARRAY(NDRPOINTER):
    referent = (
        ('Data', FW_HYPERV_RULE_METADATA_ARRAY),
    )

class FW_HYPERV_RULE_METADATA_LIST(NDRSTRUCT):
    structure = (
        ('numEntries', DWORD),
        ('list', PFW_HYPERV_RULE_METADATA_ARRAY),
    )

class FW_HYPERV_RULE0(NDRSTRUCT):
    structure = (
        ('next', PVOID),
        ('schemaVersion', WORD),
        ('ruleId', LPWSTR),
        ('ruleName', LPWSTR),
        ('priority', WORD),
        ('direction', FW_DIRECTION),
        ('vmCreatorId', GUID),
        ('protocol', WORD),
        ('localAddresses', FW_ADDRESSES),
        ('localPorts', FW_PORTS),
        ('remoteAddresses', FW_ADDRESSES),
        ('remotePorts', FW_PORTS),
        ('action', FW_RULE_ACTION),
        ('flags', WORD),
        ('status', FW_HYPERV_RULE_STATUS),
        ('origin', FW_RULE_ORIGIN_TYPE),
        ('metadataList', FW_HYPERV_RULE_METADATA_LIST),
    )

class FW_HYPERV_RULE1(NDRSTRUCT):
    structure = (
        ('next', PVOID),
        ('schemaVersion', WORD),
        ('ruleId', LPWSTR),
        ('ruleName', LPWSTR),
        ('priority', WORD),
        ('direction', FW_DIRECTION),
        ('vmCreatorId', GUID),
        ('protocol', WORD),
        ('localAddresses', FW_ADDRESSES),
        ('localPorts', FW_PORTS),
        ('remoteAddresses', FW_ADDRESSES),
        ('remotePorts', FW_PORTS),
        ('action', FW_RULE_ACTION),
        ('flags', WORD),
        ('status', FW_HYPERV_RULE_STATUS),
        ('origin', FW_RULE_ORIGIN_TYPE),
        ('metadataList', FW_HYPERV_RULE_METADATA_LIST),
        ('profileTypes', DWORD),
    )

class PFW_RULE_STATUS(NDRPOINTER):
    referent = (
        ('Data', FW_RULE_STATUS),
    )

class PFW_RULE_ORIGIN_TYPE(NDRPOINTER):
    referent = (
        ('Data', FW_RULE_ORIGIN_TYPE),
    )

class FW_PROFILE_CONFIG_VALUE(NDRUNION):
    union = {
        FW_PROFILE_CONFIG.FW_PROFILE_CONFIG_LOG_FILE_PATH : ('LogFilePath', LPWSTR),
        FW_PROFILE_CONFIG.FW_PROFILE_CONFIG_DISABLED_INTERFACES : ('DisabledInterfaces', PFW_INTERFACE_LUIDS),
        'default' : ('Value', DWORD),
    }

################################################################################
# RPC CALLS
################################################################################

# RRPC_FWOpenPolicyStore (Opnum 0)
class FWOpenPolicyStore(NDRCALL):
    opnum = 0
    structure = (
        ('BinaryVersion', WORD),
        ('StoreType', FW_STORE_TYPE),
        ('AccessRight', FW_POLICY_ACCESS_RIGHT),
        ('dwFlags', DWORD),
    )

class FWOpenPolicyStoreResponse(NDRCALL):
    structure = (
        ('phPolicyStore', FW_POLICY_STORE_HANDLE),
        ('ErrorCode', DWORD),
    )

RRPC_FWOpenPolicyStore = FWOpenPolicyStore
RRPC_FWOpenPolicyStoreResponse = FWOpenPolicyStoreResponse

# RRPC_FWClosePolicyStore (Opnum 1)
class FWClosePolicyStore(NDRCALL):
    opnum = 1
    structure = (
        ('phPolicyStore', FW_POLICY_STORE_HANDLE),
    )

class FWClosePolicyStoreResponse(NDRCALL):
    structure = (
        ('phPolicyStore', FW_POLICY_STORE_HANDLE),
        ('ErrorCode', DWORD),
    )

RRPC_FWClosePolicyStore = FWClosePolicyStore
RRPC_FWClosePolicyStoreResponse = FWClosePolicyStoreResponse

# RRPC_FWRestoreDefaults (Opnum 2)
class FWRestoreDefaults(NDRCALL):
    opnum = 2
    structure = ()

class FWRestoreDefaultsResponse(NDRCALL):
    structure = (
        ('ErrorCode', DWORD),
    )

RRPC_FWRestoreDefaults = FWRestoreDefaults
RRPC_FWRestoreDefaultsResponse = FWRestoreDefaultsResponse

# RRPC_FWGetGlobalConfig (Opnum 3)
class FWGetGlobalConfig(NDRCALL):
    opnum = 3
    structure = (
        ('BinaryVersion', WORD),
        ('StoreType', FW_STORE_TYPE),
        ('configID', FW_GLOBAL_CONFIG),
        ('dwFlags', DWORD),
        ('pBuffer', PBYTE_ARRAY),
        ('cbData', DWORD),
        ('pcbTransmittedLen', LPDWORD),
    )

class FWGetGlobalConfigResponse(NDRCALL):
    structure = (
        ('pcbTransmittedLen', LPDWORD),
        ('pcbRequired', LPDWORD),
        ('ErrorCode', DWORD),
    )

RRPC_FWGetGlobalConfig = FWGetGlobalConfig
RRPC_FWGetGlobalConfigResponse = FWGetGlobalConfigResponse

# RRPC_FWSetGlobalConfig (Opnum 4)
class FWSetGlobalConfig(NDRCALL):
    opnum = 4
    structure = (
        ('BinaryVersion', WORD),
        ('StoreType', FW_STORE_TYPE),
        ('configID', FW_GLOBAL_CONFIG),
        ('lpBuffer', PBYTE_ARRAY),
        ('dwBufSize', DWORD),
    )

class FWSetGlobalConfigResponse(NDRCALL):
    structure = (
        ('ErrorCode', DWORD),
    )

RRPC_FWSetGlobalConfig = FWSetGlobalConfig
RRPC_FWSetGlobalConfigResponse = FWSetGlobalConfigResponse

# RRPC_FWAddFirewallRule (Opnum 5)
class FWAddFirewallRule(NDRCALL):
    opnum = 5
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
        ('pRule', PFW_RULE2_0),
    )

class FWAddFirewallRuleResponse(NDRCALL):
    structure = (
        ('ErrorCode', DWORD),
    )

RRPC_FWAddFirewallRule = FWAddFirewallRule
RRPC_FWAddFirewallRuleResponse = FWAddFirewallRuleResponse

# RRPC_FWSetFirewallRule (Opnum 6)
class FWSetFirewallRule(NDRCALL):
    opnum = 6
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
        ('pRule', PFW_RULE2_0),
    )

class FWSetFirewallRuleResponse(NDRCALL):
    structure = (
        ('ErrorCode', DWORD),
    )

RRPC_FWSetFirewallRule = FWSetFirewallRule
RRPC_FWSetFirewallRuleResponse = FWSetFirewallRuleResponse

# RRPC_FWDeleteFirewallRule (Opnum 7)
class FWDeleteFirewallRule(NDRCALL):
    opnum = 7
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
        ('wszRuleID', LPWSTR),
    )

class FWDeleteFirewallRuleResponse(NDRCALL):
    structure = (
        ('ErrorCode', DWORD),
    )

RRPC_FWDeleteFirewallRule = FWDeleteFirewallRule
RRPC_FWDeleteFirewallRuleResponse = FWDeleteFirewallRuleResponse

# RRPC_FWDeleteAllFirewallRules (Opnum 8)
class FWDeleteAllFirewallRules(NDRCALL):
    opnum = 8
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
    )

class FWDeleteAllFirewallRulesResponse(NDRCALL):
    structure = (
        ('ErrorCode', DWORD),
    )

RRPC_FWDeleteAllFirewallRules = FWDeleteAllFirewallRules
RRPC_FWDeleteAllFirewallRulesResponse = FWDeleteAllFirewallRulesResponse

# RRPC_FWEnumFirewallRules (Opnum 9)
class FWEnumFirewallRules(NDRCALL):
    opnum = 9
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
        ('dwFilteredByStatus', DWORD),
        ('dwProfileFilter', DWORD),
        ('wFlags', WORD),
    )

class FWEnumFirewallRulesResponse(NDRCALL):
    structure = (
        ('pdwNumRules', LPDWORD),
        ('ppRules', PFW_RULE2_0_ARRAY),
        ('ErrorCode', DWORD),
    )

RRPC_FWEnumFirewallRules = FWEnumFirewallRules
RRPC_FWEnumFirewallRulesResponse = FWEnumFirewallRulesResponse

# RRPC_FWGetConfig (Opnum 10)
class FWGetConfig(NDRCALL):
    opnum = 10
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
        ('configID', FW_PROFILE_CONFIG),
        ('Profile', FW_PROFILE_TYPE),
        ('dwFlags', DWORD),
        ('pBuffer', PBYTE_ARRAY),
        ('cbData', DWORD),
        ('pcbTransmittedLen', LPDWORD),
    )

class FWGetConfigResponse(NDRCALL):
    structure = (
        ('pcbTransmittedLen', LPDWORD),
        ('pcbRequired', LPDWORD),
        ('ErrorCode', DWORD),
    )

RRPC_FWGetConfig = FWGetConfig
RRPC_FWGetConfigResponse = FWGetConfigResponse

# RRPC_FWSetConfig (Opnum 11)
class FWSetConfig(NDRCALL):
    opnum = 11
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
        ('configID', FW_PROFILE_CONFIG),
        ('Profile', FW_PROFILE_TYPE),
        ('pConfig', FW_PROFILE_CONFIG_VALUE),
        ('dwBufSize', DWORD),
    )

class FWSetConfigResponse(NDRCALL):
    structure = (
        ('ErrorCode', DWORD),
    )

RRPC_FWSetConfig = FWSetConfig
RRPC_FWSetConfigResponse = FWSetConfigResponse

# RRPC_FWAddConnectionSecurityRule (Opnum 12)
class FWAddConnectionSecurityRule(NDRCALL):
    opnum = 12
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
        ('pRule', PFW_CS_RULE2_0),
    )

class FWAddConnectionSecurityRuleResponse(NDRCALL):
    structure = (
        ('ErrorCode', DWORD),
    )

RRPC_FWAddConnectionSecurityRule = FWAddConnectionSecurityRule
RRPC_FWAddConnectionSecurityRuleResponse = FWAddConnectionSecurityRuleResponse

# RRPC_FWSetConnectionSecurityRule (Opnum 13)
class FWSetConnectionSecurityRule(NDRCALL):
    opnum = 13
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
        ('pRule', PFW_CS_RULE2_0),
    )

class FWSetConnectionSecurityRuleResponse(NDRCALL):
    structure = (
        ('ErrorCode', DWORD),
    )

RRPC_FWSetConnectionSecurityRule = FWSetConnectionSecurityRule
RRPC_FWSetConnectionSecurityRuleResponse = FWSetConnectionSecurityRuleResponse

# RRPC_FWDeleteConnectionSecurityRule (Opnum 14)
class FWDeleteConnectionSecurityRule(NDRCALL):
    opnum = 14
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
        ('pRuleId', LPWSTR),
    )

class FWDeleteConnectionSecurityRuleResponse(NDRCALL):
    structure = (
        ('ErrorCode', DWORD),
    )

RRPC_FWDeleteConnectionSecurityRule = FWDeleteConnectionSecurityRule
RRPC_FWDeleteConnectionSecurityRuleResponse = FWDeleteConnectionSecurityRuleResponse

# RRPC_FWDeleteAllConnectionSecurityRules (Opnum 15)
class FWDeleteAllConnectionSecurityRules(NDRCALL):
    opnum = 15
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
    )

class FWDeleteAllConnectionSecurityRulesResponse(NDRCALL):
    structure = (
        ('ErrorCode', DWORD),
    )

RRPC_FWDeleteAllConnectionSecurityRules = FWDeleteAllConnectionSecurityRules
RRPC_FWDeleteAllConnectionSecurityRulesResponse = FWDeleteAllConnectionSecurityRulesResponse

# RRPC_FWEnumConnectionSecurityRules (Opnum 16)
class FWEnumConnectionSecurityRules(NDRCALL):
    opnum = 16
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
        ('dwFilteredByStatus', DWORD),
        ('dwProfileFilter', DWORD),
        ('wFlags', WORD),
    )

class FWEnumConnectionSecurityRulesResponse(NDRCALL):
    structure = (
        ('pdwNumRules', LPDWORD),
        ('ppRules', PFW_CS_RULE2_0_ARRAY),
        ('ErrorCode', DWORD),
    )

RRPC_FWEnumConnectionSecurityRules = FWEnumConnectionSecurityRules
RRPC_FWEnumConnectionSecurityRulesResponse = FWEnumConnectionSecurityRulesResponse

# RRPC_FWAddAuthenticationSet (Opnum 17)
class FWAddAuthenticationSet(NDRCALL):
    opnum = 17
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
        ('pAuth', PFW_AUTH_SET2_10),
    )

class FWAddAuthenticationSetResponse(NDRCALL):
    structure = (
        ('ErrorCode', DWORD),
    )

RRPC_FWAddAuthenticationSet = FWAddAuthenticationSet
RRPC_FWAddAuthenticationSetResponse = FWAddAuthenticationSetResponse

# RRPC_FWSetAuthenticationSet (Opnum 18)
class FWSetAuthenticationSet(NDRCALL):
    opnum = 18
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
        ('pAuth', PFW_AUTH_SET2_10),
    )

class FWSetAuthenticationSetResponse(NDRCALL):
    structure = (
        ('ErrorCode', DWORD),
    )

RRPC_FWSetAuthenticationSet = FWSetAuthenticationSet
RRPC_FWSetAuthenticationSetResponse = FWSetAuthenticationSetResponse

# RRPC_FWDeleteAuthenticationSet (Opnum 19)
class FWDeleteAuthenticationSet(NDRCALL):
    opnum = 19
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
        ('IpSecPhase', FW_IPSEC_PHASE),
        ('wszSetId', LPWSTR),
    )

class FWDeleteAuthenticationSetResponse(NDRCALL):
    structure = (
        ('ErrorCode', DWORD),
    )

RRPC_FWDeleteAuthenticationSet = FWDeleteAuthenticationSet
RRPC_FWDeleteAuthenticationSetResponse = FWDeleteAuthenticationSetResponse

# RRPC_FWDeleteAllAuthenticationSets (Opnum 20)
class FWDeleteAllAuthenticationSets(NDRCALL):
    opnum = 20
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
        ('IpSecPhase', FW_IPSEC_PHASE),
    )

class FWDeleteAllAuthenticationSetsResponse(NDRCALL):
    structure = (
        ('ErrorCode', DWORD),
    )

RRPC_FWDeleteAllAuthenticationSets = FWDeleteAllAuthenticationSets
RRPC_FWDeleteAllAuthenticationSetsResponse = FWDeleteAllAuthenticationSetsResponse

# RRPC_FWEnumAuthenticationSets (Opnum 21)
class FWEnumAuthenticationSets(NDRCALL):
    opnum = 21
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
        ('IpSecPhase', FW_IPSEC_PHASE),
        ('dwFilteredByStatus', DWORD),
        ('wFlags', WORD),
    )

class FWEnumAuthenticationSetsResponse(NDRCALL):
    structure = (
        ('pdwNumAuthSets', LPDWORD),
        ('ppAuth', PFW_AUTH_SET2_10_ARRAY),
        ('ErrorCode', DWORD),
    )

RRPC_FWEnumAuthenticationSets = FWEnumAuthenticationSets
RRPC_FWEnumAuthenticationSetsResponse = FWEnumAuthenticationSetsResponse

# RRPC_FWAddCryptoSet (Opnum 22)
class FWAddCryptoSet(NDRCALL):
    opnum = 22
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
        ('pCrypto', PFW_CRYPTO_SET),
    )

class FWAddCryptoSetResponse(NDRCALL):
    structure = (
        ('ErrorCode', DWORD),
    )

RRPC_FWAddCryptoSet = FWAddCryptoSet
RRPC_FWAddCryptoSetResponse = FWAddCryptoSetResponse

# RRPC_FWSetCryptoSet (Opnum 23)
class FWSetCryptoSet(NDRCALL):
    opnum = 23
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
        ('pCrypto', PFW_CRYPTO_SET),
    )

class FWSetCryptoSetResponse(NDRCALL):
    structure = (
        ('ErrorCode', DWORD),
    )

RRPC_FWSetCryptoSet = FWSetCryptoSet
RRPC_FWSetCryptoSetResponse = FWSetCryptoSetResponse

# RRPC_FWDeleteCryptoSet (Opnum 24)
class FWDeleteCryptoSet(NDRCALL):
    opnum = 24
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
        ('IpSecPhase', FW_IPSEC_PHASE),
        ('wszSetId', LPWSTR),
    )

class FWDeleteCryptoSetResponse(NDRCALL):
    structure = (
        ('ErrorCode', DWORD),
    )

RRPC_FWDeleteCryptoSet = FWDeleteCryptoSet
RRPC_FWDeleteCryptoSetResponse = FWDeleteCryptoSetResponse

# RRPC_FWDeleteAllCryptoSets (Opnum 25)
class FWDeleteAllCryptoSets(NDRCALL):
    opnum = 25
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
        ('IpSecPhase', FW_IPSEC_PHASE),
    )

class FWDeleteAllCryptoSetsResponse(NDRCALL):
    structure = (
        ('ErrorCode', DWORD),
    )

RRPC_FWDeleteAllCryptoSets = FWDeleteAllCryptoSets
RRPC_FWDeleteAllCryptoSetsResponse = FWDeleteAllCryptoSetsResponse

# RRPC_FWEnumCryptoSets (Opnum 26)
class FWEnumCryptoSets(NDRCALL):
    opnum = 26
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
        ('IpSecPhase', FW_IPSEC_PHASE),
        ('dwFilteredByStatus', DWORD),
        ('wFlags', WORD),
    )

class FWEnumCryptoSetsResponse(NDRCALL):
    structure = (
        ('pdwNumSets', LPDWORD),
        ('ppCryptoSets', PFW_CRYPTO_SET_ARRAY),
        ('ErrorCode', DWORD),
    )

RRPC_FWEnumCryptoSets = FWEnumCryptoSets
RRPC_FWEnumCryptoSetsResponse = FWEnumCryptoSetsResponse

# RRPC_FWEnumPhase1SAs (Opnum 27)
class FWEnumPhase1SAs(NDRCALL):
    opnum = 27
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
        ('pEndpoints', PFW_ENDPOINTS),
    )

class FWEnumPhase1SAsResponse(NDRCALL):
    structure = (
        ('pdwNumSAs', LPDWORD),
        ('ppSAs', PFW_PHASE1_SA_DETAILS_ARRAY),
        ('ErrorCode', DWORD),
    )

RRPC_FWEnumPhase1SAs = FWEnumPhase1SAs
RRPC_FWEnumPhase1SAsResponse = FWEnumPhase1SAsResponse

# RRPC_FWEnumPhase2SAs (Opnum 28)
class FWEnumPhase2SAs(NDRCALL):
    opnum = 28
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
        ('pEndpoints', PFW_ENDPOINTS),
    )

class FWEnumPhase2SAsResponse(NDRCALL):
    structure = (
        ('pdwNumSAs', LPDWORD),
        ('ppSAs', PFW_PHASE2_SA_DETAILS_ARRAY),
        ('ErrorCode', DWORD),
    )

RRPC_FWEnumPhase2SAs = FWEnumPhase2SAs
RRPC_FWEnumPhase2SAsResponse = FWEnumPhase2SAsResponse

# RRPC_FWDeletePhase1SAs (Opnum 29)
class FWDeletePhase1SAs(NDRCALL):
    opnum = 29
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
        ('pEndpoints', PFW_ENDPOINTS),
    )

class FWDeletePhase1SAsResponse(NDRCALL):
    structure = (
        ('ErrorCode', DWORD),
    )

RRPC_FWDeletePhase1SAs = FWDeletePhase1SAs
RRPC_FWDeletePhase1SAsResponse = FWDeletePhase1SAsResponse

# RRPC_FWDeletePhase2SAs (Opnum 30)
class FWDeletePhase2SAs(NDRCALL):
    opnum = 30
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
        ('pEndpoints', PFW_ENDPOINTS),
    )

class FWDeletePhase2SAsResponse(NDRCALL):
    structure = (
        ('ErrorCode', DWORD),
    )

RRPC_FWDeletePhase2SAs = FWDeletePhase2SAs
RRPC_FWDeletePhase2SAsResponse = FWDeletePhase2SAsResponse

# RRPC_FWEnumProducts (Opnum 31)
class FWEnumProducts(NDRCALL):
    opnum = 31
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
    )

class FWEnumProductsResponse(NDRCALL):
    structure = (
        ('pdwNumProducts', LPDWORD),
        ('ppProducts', PFW_PRODUCT_ARRAY),
        ('ErrorCode', DWORD),
    )

RRPC_FWEnumProducts = FWEnumProducts
RRPC_FWEnumProductsResponse = FWEnumProductsResponse

# RRPC_FWAddMainModeRule (Opnum 32)
class FWAddMainModeRule(NDRCALL):
    opnum = 32
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
        ('pMMRule', PFW_MM_RULE),
    )

class FWAddMainModeRuleResponse(NDRCALL):
    structure = (
        ('pStatus', PFW_RULE_STATUS),
        ('ErrorCode', DWORD),
    )

RRPC_FWAddMainModeRule = FWAddMainModeRule
RRPC_FWAddMainModeRuleResponse = FWAddMainModeRuleResponse

# RRPC_FWSetMainModeRule (Opnum 33)
class FWSetMainModeRule(NDRCALL):
    opnum = 33
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
        ('pMMRule', PFW_MM_RULE),
    )

class FWSetMainModeRuleResponse(NDRCALL):
    structure = (
        ('pStatus', PFW_RULE_STATUS),
        ('ErrorCode', DWORD),
    )

RRPC_FWSetMainModeRule = FWSetMainModeRule
RRPC_FWSetMainModeRuleResponse = FWSetMainModeRuleResponse

# RRPC_FWDeleteMainModeRule (Opnum 34)
class FWDeleteMainModeRule(NDRCALL):
    opnum = 34
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
        ('pRuleId', LPWSTR),
    )

class FWDeleteMainModeRuleResponse(NDRCALL):
    structure = (
        ('ErrorCode', DWORD),
    )

RRPC_FWDeleteMainModeRule = FWDeleteMainModeRule
RRPC_FWDeleteMainModeRuleResponse = FWDeleteMainModeRuleResponse

# RRPC_FWDeleteAllMainModeRules (Opnum 35)
class FWDeleteAllMainModeRules(NDRCALL):
    opnum = 35
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
    )

class FWDeleteAllMainModeRulesResponse(NDRCALL):
    structure = (
        ('ErrorCode', DWORD),
    )

RRPC_FWDeleteAllMainModeRules = FWDeleteAllMainModeRules
RRPC_FWDeleteAllMainModeRulesResponse = FWDeleteAllMainModeRulesResponse

# RRPC_FWEnumMainModeRules (Opnum 36)
class FWEnumMainModeRules(NDRCALL):
    opnum = 36
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
        ('dwFilteredByStatus', DWORD),
        ('dwProfileFilter', DWORD),
        ('wFlags', WORD),
    )

class FWEnumMainModeRulesResponse(NDRCALL):
    structure = (
        ('pdwNumRules', LPDWORD),
        ('ppMMRules', PFW_MM_RULE_ARRAY),
        ('ErrorCode', DWORD),
    )

RRPC_FWEnumMainModeRules = FWEnumMainModeRules
RRPC_FWEnumMainModeRulesResponse = FWEnumMainModeRulesResponse

# RRPC_FWQueryFirewallRules (Opnum 37)
class FWQueryFirewallRules(NDRCALL):
    opnum = 37
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
        ('pQuery', PFW_QUERY),
        ('wFlags', WORD),
    )

class FWQueryFirewallRulesResponse(NDRCALL):
    structure = (
        ('pdwNumRules', LPDWORD),
        ('ppRules', PFW_RULE2_10_ARRAY),
        ('ErrorCode', DWORD),
    )

RRPC_FWQueryFirewallRules = FWQueryFirewallRules
RRPC_FWQueryFirewallRulesResponse = FWQueryFirewallRulesResponse

# RRPC_FWQueryConnectionSecurityRules2_10 (Opnum 38)
class FWQueryConnectionSecurityRules2_10(NDRCALL):
    opnum = 38
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
        ('pQuery', PFW_QUERY),
        ('wFlags', WORD),
    )

class FWQueryConnectionSecurityRules2_10Response(NDRCALL):
    structure = (
        ('pdwNumRules', LPDWORD),
        ('ppRules', PFW_CS_RULE2_10_ARRAY),
        ('ErrorCode', DWORD),
    )

RRPC_FWQueryConnectionSecurityRules2_10 = FWQueryConnectionSecurityRules2_10
RRPC_FWQueryConnectionSecurityRules2_10Response = FWQueryConnectionSecurityRules2_10Response

# RRPC_FWQueryMainModeRules (Opnum 39)
class FWQueryMainModeRules(NDRCALL):
    opnum = 39
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
        ('pQuery', PFW_QUERY),
        ('wFlags', WORD),
    )

class FWQueryMainModeRulesResponse(NDRCALL):
    structure = (
        ('pdwNumRules', LPDWORD),
        ('ppMMRules', PFW_MM_RULE_ARRAY),
        ('ErrorCode', DWORD),
    )

RRPC_FWQueryMainModeRules = FWQueryMainModeRules
RRPC_FWQueryMainModeRulesResponse = FWQueryMainModeRulesResponse

# RRPC_FWQueryAuthenticationSets (Opnum 40)
class FWQueryAuthenticationSets(NDRCALL):
    opnum = 40
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
        ('IPsecPhase', FW_IPSEC_PHASE),
        ('pQuery', PFW_QUERY),
        ('wFlags', WORD),
    )

class FWQueryAuthenticationSetsResponse(NDRCALL):
    structure = (
        ('pdwNumSets', LPDWORD),
        ('ppAuthSets', PFW_AUTH_SET2_10_ARRAY),
        ('ErrorCode', DWORD),
    )

RRPC_FWQueryAuthenticationSets = FWQueryAuthenticationSets
RRPC_FWQueryAuthenticationSetsResponse = FWQueryAuthenticationSetsResponse

# RRPC_FWQueryCryptoSets (Opnum 41)
class FWQueryCryptoSets(NDRCALL):
    opnum = 41
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
        ('IPsecPhase', FW_IPSEC_PHASE),
        ('pQuery', PFW_QUERY),
        ('wFlags', WORD),
    )

class FWQueryCryptoSetsResponse(NDRCALL):
    structure = (
        ('pdwNumSets', LPDWORD),
        ('ppCryptoSets', PFW_CRYPTO_SET_ARRAY),
        ('ErrorCode', DWORD),
    )

RRPC_FWQueryCryptoSets = FWQueryCryptoSets
RRPC_FWQueryCryptoSetsResponse = FWQueryCryptoSetsResponse

# RRPC_FWEnumNetworks (Opnum 42)
class FWEnumNetworks(NDRCALL):
    opnum = 42
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
    )

class FWEnumNetworksResponse(NDRCALL):
    structure = (
        ('pdwNumNetworks', LPDWORD),
        ('ppNetworks', PFW_NETWORK_ARRAY),
        ('ErrorCode', DWORD),
    )

RRPC_FWEnumNetworks = FWEnumNetworks
RRPC_FWEnumNetworksResponse = FWEnumNetworksResponse

# RRPC_FWEnumAdapters (Opnum 43)
class FWEnumAdapters(NDRCALL):
    opnum = 43
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
    )

class FWEnumAdaptersResponse(NDRCALL):
    structure = (
        ('pdwNumAdapters', LPDWORD),
        ('ppAdapters', PFW_ADAPTER_ARRAY),
        ('ErrorCode', DWORD),
    )

RRPC_FWEnumAdapters = FWEnumAdapters
RRPC_FWEnumAdaptersResponse = FWEnumAdaptersResponse

# RRPC_FWGetGlobalConfig2_10 (Opnum 44)
class FWGetGlobalConfig2_10(NDRCALL):
    opnum = 44
    structure = (
        ('BinaryVersion', WORD),
        ('StoreType', FW_STORE_TYPE),
        ('configID', FW_GLOBAL_CONFIG),
        ('dwFlags', DWORD),
        ('pBuffer', PBYTE_ARRAY),
        ('cbData', DWORD),
        ('pcbTransmittedLen', LPDWORD),
    )

class FWGetGlobalConfig2_10Response(NDRCALL):
    structure = (
        ('pcbTransmittedLen', LPDWORD),
        ('pcbRequired', LPDWORD),
        ('pOrigin', PFW_RULE_ORIGIN_TYPE),
        ('ErrorCode', DWORD),
    )

RRPC_FWGetGlobalConfig2_10 = FWGetGlobalConfig2_10
RRPC_FWGetGlobalConfig2_10Response = FWGetGlobalConfig2_10Response

# RRPC_FWGetConfig2_10 (Opnum 45)
class FWGetConfig2_10(NDRCALL):
    opnum = 45
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
        ('configID', FW_PROFILE_CONFIG),
        ('Profile', FW_PROFILE_TYPE),
        ('dwFlags', DWORD),
        ('pBuffer', PBYTE_ARRAY),
        ('cbData', DWORD),
        ('pcbTransmittedLen', LPDWORD),
    )

class FWGetConfig2_10Response(NDRCALL):
    structure = (
        ('pcbTransmittedLen', LPDWORD),
        ('pcbRequired', LPDWORD),
        ('pOrigin', PFW_RULE_ORIGIN_TYPE),
        ('ErrorCode', DWORD),
    )

RRPC_FWGetConfig2_10 = FWGetConfig2_10
RRPC_FWGetConfig2_10Response = FWGetConfig2_10Response

# RRPC_FWAddFirewallRule2_10 (Opnum 46)
class FWAddFirewallRule2_10(NDRCALL):
    opnum = 46
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
        ('pRule', PFW_RULE2_10),
    )

class FWAddFirewallRule2_10Response(NDRCALL):
    structure = (
        ('pStatus', PFW_RULE_STATUS),
        ('ErrorCode', DWORD),
    )

RRPC_FWAddFirewallRule2_10 = FWAddFirewallRule2_10
RRPC_FWAddFirewallRule2_10Response = FWAddFirewallRule2_10Response

# RRPC_FWSetFirewallRule2_10 (Opnum 47)
class FWSetFirewallRule2_10(NDRCALL):
    opnum = 47
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
        ('pRule', PFW_RULE2_10),
    )

class FWSetFirewallRule2_10Response(NDRCALL):
    structure = (
        ('pStatus', PFW_RULE_STATUS),
        ('ErrorCode', DWORD),
    )

RRPC_FWSetFirewallRule2_10 = FWSetFirewallRule2_10
RRPC_FWSetFirewallRule2_10Response = FWSetFirewallRule2_10Response

# RRPC_FWEnumFirewallRules2_10 (Opnum 48)
class FWEnumFirewallRules2_10(NDRCALL):
    opnum = 48
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
        ('dwFilteredByStatus', DWORD),
        ('dwProfileFilter', DWORD),
        ('wFlags', WORD),
    )

class FWEnumFirewallRules2_10Response(NDRCALL):
    structure = (
        ('pdwNumRules', LPDWORD),
        ('ppRules', PFW_RULE2_10_ARRAY),
        ('ErrorCode', DWORD),
    )

RRPC_FWEnumFirewallRules2_10 = FWEnumFirewallRules2_10
RRPC_FWEnumFirewallRules2_10Response = FWEnumFirewallRules2_10Response

# RRPC_FWAddConnectionSecurityRule2_10 (Opnum 49)
class FWAddConnectionSecurityRule2_10(NDRCALL):
    opnum = 49
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
        ('pRule', PFW_CS_RULE2_10),
    )

class FWAddConnectionSecurityRule2_10Response(NDRCALL):
    structure = (
        ('pStatus', PFW_RULE_STATUS),
        ('ErrorCode', DWORD),
    )

RRPC_FWAddConnectionSecurityRule2_10 = FWAddConnectionSecurityRule2_10
RRPC_FWAddConnectionSecurityRule2_10Response = FWAddConnectionSecurityRule2_10Response

# RRPC_FWSetConnectionSecurityRule2_10 (Opnum 50)
class FWSetConnectionSecurityRule2_10(NDRCALL):
    opnum = 50
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
        ('pRule', PFW_CS_RULE2_10),
    )

class FWSetConnectionSecurityRule2_10Response(NDRCALL):
    structure = (
        ('pStatus', PFW_RULE_STATUS),
        ('ErrorCode', DWORD),
    )

RRPC_FWSetConnectionSecurityRule2_10 = FWSetConnectionSecurityRule2_10
RRPC_FWSetConnectionSecurityRule2_10Response = FWSetConnectionSecurityRule2_10Response

# RRPC_FWEnumConnectionSecurityRules2_10 (Opnum 51)
class FWEnumConnectionSecurityRules2_10(NDRCALL):
    opnum = 51
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
        ('dwFilteredByStatus', DWORD),
        ('dwProfileFilter', DWORD),
        ('wFlags', WORD),
    )

class FWEnumConnectionSecurityRules2_10Response(NDRCALL):
    structure = (
        ('pdwNumRules', LPDWORD),
        ('ppRules', PFW_CS_RULE2_10_ARRAY),
        ('ErrorCode', DWORD),
    )

RRPC_FWEnumConnectionSecurityRules2_10 = FWEnumConnectionSecurityRules2_10
RRPC_FWEnumConnectionSecurityRules2_10Response = FWEnumConnectionSecurityRules2_10Response

# RRPC_FWAddAuthenticationSet2_10 (Opnum 52)
class FWAddAuthenticationSet2_10(NDRCALL):
    opnum = 52
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
        ('pAuth', PFW_AUTH_SET2_10),
    )

class FWAddAuthenticationSet2_10Response(NDRCALL):
    structure = (
        ('pStatus', PFW_RULE_STATUS),
        ('ErrorCode', DWORD),
    )

RRPC_FWAddAuthenticationSet2_10 = FWAddAuthenticationSet2_10
RRPC_FWAddAuthenticationSet2_10Response = FWAddAuthenticationSet2_10Response

# RRPC_FWSetAuthenticationSet2_10 (Opnum 53)
class FWSetAuthenticationSet2_10(NDRCALL):
    opnum = 53
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
        ('pAuth', PFW_AUTH_SET2_10),
    )

class FWSetAuthenticationSet2_10Response(NDRCALL):
    structure = (
        ('pStatus', PFW_RULE_STATUS),
        ('ErrorCode', DWORD),
    )

RRPC_FWSetAuthenticationSet2_10 = FWSetAuthenticationSet2_10
RRPC_FWSetAuthenticationSet2_10Response = FWSetAuthenticationSet2_10Response

# RRPC_FWEnumAuthenticationSets2_10 (Opnum 54)
class FWEnumAuthenticationSets2_10(NDRCALL):
    opnum = 54
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
        ('IpSecPhase', FW_IPSEC_PHASE),
        ('dwFilteredByStatus', DWORD),
        ('wFlags', WORD),
    )

class FWEnumAuthenticationSets2_10Response(NDRCALL):
    structure = (
        ('pdwNumAuthSets', LPDWORD),
        ('ppAuth', PFW_AUTH_SET2_10_ARRAY),
        ('ErrorCode', DWORD),
    )

RRPC_FWEnumAuthenticationSets2_10 = FWEnumAuthenticationSets2_10
RRPC_FWEnumAuthenticationSets2_10Response = FWEnumAuthenticationSets2_10Response

# RRPC_FWAddCryptoSet2_10 (Opnum 55)
class FWAddCryptoSet2_10(NDRCALL):
    opnum = 55
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
        ('pCrypto', PFW_CRYPTO_SET),
    )

class FWAddCryptoSet2_10Response(NDRCALL):
    structure = (
        ('pStatus', PFW_RULE_STATUS),
        ('ErrorCode', DWORD),
    )

RRPC_FWAddCryptoSet2_10 = FWAddCryptoSet2_10
RRPC_FWAddCryptoSet2_10Response = FWAddCryptoSet2_10Response

# RRPC_FWSetCryptoSet2_10 (Opnum 56)
class FWSetCryptoSet2_10(NDRCALL):
    opnum = 56
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
        ('pCrypto', PFW_CRYPTO_SET),
    )

class FWSetCryptoSet2_10Response(NDRCALL):
    structure = (
        ('pStatus', PFW_RULE_STATUS),
        ('ErrorCode', DWORD),
    )

RRPC_FWSetCryptoSet2_10 = FWSetCryptoSet2_10
RRPC_FWSetCryptoSet2_10Response = FWSetCryptoSet2_10Response

# RRPC_FWEnumCryptoSets2_10 (Opnum 57)
class FWEnumCryptoSets2_10(NDRCALL):
    opnum = 57
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
        ('IpSecPhase', FW_IPSEC_PHASE),
        ('dwFilteredByStatus', DWORD),
        ('wFlags', WORD),
    )

class FWEnumCryptoSets2_10Response(NDRCALL):
    structure = (
        ('pdwNumSets', LPDWORD),
        ('ppCryptoSets', PFW_CRYPTO_SET_ARRAY),
        ('ErrorCode', DWORD),
    )

RRPC_FWEnumCryptoSets2_10 = FWEnumCryptoSets2_10
RRPC_FWEnumCryptoSets2_10Response = FWEnumCryptoSets2_10Response

# RRPC_FWAddConnectionSecurityRule2_20 (Opnum 58)
class FWAddConnectionSecurityRule2_20(NDRCALL):
    opnum = 58
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
        ('pRule', PFW_CS_RULE),
    )

class FWAddConnectionSecurityRule2_20Response(NDRCALL):
    structure = (
        ('pStatus', PFW_RULE_STATUS),
        ('ErrorCode', DWORD),
    )

RRPC_FWAddConnectionSecurityRule2_20 = FWAddConnectionSecurityRule2_20
RRPC_FWAddConnectionSecurityRule2_20Response = FWAddConnectionSecurityRule2_20Response

# RRPC_FWSetConnectionSecurityRule2_20 (Opnum 59)
class FWSetConnectionSecurityRule2_20(NDRCALL):
    opnum = 59
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
        ('pRule', PFW_CS_RULE),
    )

class FWSetConnectionSecurityRule2_20Response(NDRCALL):
    structure = (
        ('pStatus', PFW_RULE_STATUS),
        ('ErrorCode', DWORD),
    )

RRPC_FWSetConnectionSecurityRule2_20 = FWSetConnectionSecurityRule2_20
RRPC_FWSetConnectionSecurityRule2_20Response = FWSetConnectionSecurityRule2_20Response

# RRPC_FWEnumConnectionSecurityRules2_20 (Opnum 60)
class FWEnumConnectionSecurityRules2_20(NDRCALL):
    opnum = 60
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
        ('dwFilteredByStatus', DWORD),
        ('dwProfileFilter', DWORD),
        ('wFlags', WORD),
    )

class FWEnumConnectionSecurityRules2_20Response(NDRCALL):
    structure = (
        ('pdwNumRules', LPDWORD),
        ('ppRules', PFW_CS_RULE_ARRAY),
        ('ErrorCode', DWORD),
    )

RRPC_FWEnumConnectionSecurityRules2_20 = FWEnumConnectionSecurityRules2_20
RRPC_FWEnumConnectionSecurityRules2_20Response = FWEnumConnectionSecurityRules2_20Response

# RRPC_FWQueryConnectionSecurityRules2_20 (Opnum 61)
class FWQueryConnectionSecurityRules2_20(NDRCALL):
    opnum = 61
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
        ('pQuery', PFW_QUERY),
        ('wFlags', WORD),
    )

class FWQueryConnectionSecurityRules2_20Response(NDRCALL):
    structure = (
        ('pdwNumRules', LPDWORD),
        ('ppRules', PFW_CS_RULE_ARRAY),
        ('ErrorCode', DWORD),
    )

RRPC_FWQueryConnectionSecurityRules2_20 = FWQueryConnectionSecurityRules2_20
RRPC_FWQueryConnectionSecurityRules2_20Response = FWQueryConnectionSecurityRules2_20Response

# RRPC_FWAddAuthenticationSet2_20 (Opnum 62)
class FWAddAuthenticationSet2_20(NDRCALL):
    opnum = 62
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
        ('pAuth', PFW_AUTH_SET),
    )

class FWAddAuthenticationSet2_20Response(NDRCALL):
    structure = (
        ('pStatus', PFW_RULE_STATUS),
        ('ErrorCode', DWORD),
    )

RRPC_FWAddAuthenticationSet2_20 = FWAddAuthenticationSet2_20
RRPC_FWAddAuthenticationSet2_20Response = FWAddAuthenticationSet2_20Response

# RRPC_FWSetAuthenticationSet2_20 (Opnum 63)
class FWSetAuthenticationSet2_20(NDRCALL):
    opnum = 63
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
        ('pAuth', PFW_AUTH_SET),
    )

class FWSetAuthenticationSet2_20Response(NDRCALL):
    structure = (
        ('pStatus', PFW_RULE_STATUS),
        ('ErrorCode', DWORD),
    )

RRPC_FWSetAuthenticationSet2_20 = FWSetAuthenticationSet2_20
RRPC_FWSetAuthenticationSet2_20Response = FWSetAuthenticationSet2_20Response

# RRPC_FWEnumAuthenticationSets2_20 (Opnum 64)
class FWEnumAuthenticationSets2_20(NDRCALL):
    opnum = 64
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
        ('IpSecPhase', FW_IPSEC_PHASE),
        ('dwFilteredByStatus', DWORD),
        ('wFlags', WORD),
    )

class FWEnumAuthenticationSets2_20Response(NDRCALL):
    structure = (
        ('pdwNumAuthSets', LPDWORD),
        ('ppAuth', PFW_AUTH_SET_ARRAY),
        ('ErrorCode', DWORD),
    )

RRPC_FWEnumAuthenticationSets2_20 = FWEnumAuthenticationSets2_20
RRPC_FWEnumAuthenticationSets2_20Response = FWEnumAuthenticationSets2_20Response

# RRPC_FWQueryAuthenticationSets2_20 (Opnum 65)
class FWQueryAuthenticationSets2_20(NDRCALL):
    opnum = 65
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
        ('IPsecPhase', FW_IPSEC_PHASE),
        ('pQuery', PFW_QUERY),
        ('wFlags', WORD),
    )

class FWQueryAuthenticationSets2_20Response(NDRCALL):
    structure = (
        ('pdwNumSets', LPDWORD),
        ('ppAuthSets', PFW_AUTH_SET_ARRAY),
        ('ErrorCode', DWORD),
    )

RRPC_FWQueryAuthenticationSets2_20 = FWQueryAuthenticationSets2_20
RRPC_FWQueryAuthenticationSets2_20Response = FWQueryAuthenticationSets2_20Response

# RRPC_FWAddFirewallRule2_20 (Opnum 66)
class FWAddFirewallRule2_20(NDRCALL):
    opnum = 66
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
        ('pRule', PFW_RULE2_20),
    )

class FWAddFirewallRule2_20Response(NDRCALL):
    structure = (
        ('pStatus', PFW_RULE_STATUS),
        ('ErrorCode', DWORD),
    )

RRPC_FWAddFirewallRule2_20 = FWAddFirewallRule2_20
RRPC_FWAddFirewallRule2_20Response = FWAddFirewallRule2_20Response

# RRPC_FWSetFirewallRule2_20 (Opnum 67)
class FWSetFirewallRule2_20(NDRCALL):
    opnum = 67
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
        ('pRule', PFW_RULE2_20),
    )

class FWSetFirewallRule2_20Response(NDRCALL):
    structure = (
        ('pStatus', PFW_RULE_STATUS),
        ('ErrorCode', DWORD),
    )

RRPC_FWSetFirewallRule2_20 = FWSetFirewallRule2_20
RRPC_FWSetFirewallRule2_20Response = FWSetFirewallRule2_20Response

# RRPC_FWEnumFirewallRules2_20 (Opnum 68)
class FWEnumFirewallRules2_20(NDRCALL):
    opnum = 68
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
        ('dwFilteredByStatus', DWORD),
        ('dwProfileFilter', DWORD),
        ('wFlags', WORD),
    )

class FWEnumFirewallRules2_20Response(NDRCALL):
    structure = (
        ('pdwNumRules', LPDWORD),
        ('ppRules', PFW_RULE2_20_ARRAY),
        ('ErrorCode', DWORD),
    )

RRPC_FWEnumFirewallRules2_20 = FWEnumFirewallRules2_20
RRPC_FWEnumFirewallRules2_20Response = FWEnumFirewallRules2_20Response

# RRPC_FWQueryFirewallRules2_20 (Opnum 69)
class FWQueryFirewallRules2_20(NDRCALL):
    opnum = 69
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
        ('pQuery', PFW_QUERY),
        ('wFlags', WORD),
    )

class FWQueryFirewallRules2_20Response(NDRCALL):
    structure = (
        ('pdwNumRules', LPDWORD),
        ('ppRules', PFW_RULE2_20_ARRAY),
        ('ErrorCode', DWORD),
    )

RRPC_FWQueryFirewallRules2_20 = FWQueryFirewallRules2_20
RRPC_FWQueryFirewallRules2_20Response = FWQueryFirewallRules2_20Response

# RRPC_FWAddFirewallRule2_24 (Opnum 70)
class FWAddFirewallRule2_24(NDRCALL):
    opnum = 70
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
        ('pRule', PFW_RULE2_24),
    )

class FWAddFirewallRule2_24Response(NDRCALL):
    structure = (
        ('pStatus', PFW_RULE_STATUS),
        ('ErrorCode', DWORD),
    )

RRPC_FWAddFirewallRule2_24 = FWAddFirewallRule2_24
RRPC_FWAddFirewallRule2_24Response = FWAddFirewallRule2_24Response

# RRPC_FWSetFirewallRule2_24 (Opnum 71)
class FWSetFirewallRule2_24(NDRCALL):
    opnum = 71
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
        ('pRule', PFW_RULE2_24),
    )

class FWSetFirewallRule2_24Response(NDRCALL):
    structure = (
        ('pStatus', PFW_RULE_STATUS),
        ('ErrorCode', DWORD),
    )

RRPC_FWSetFirewallRule2_24 = FWSetFirewallRule2_24
RRPC_FWSetFirewallRule2_24Response = FWSetFirewallRule2_24Response

# RRPC_FWEnumFirewallRules2_24 (Opnum 72)
class FWEnumFirewallRules2_24(NDRCALL):
    opnum = 72
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
        ('dwFilteredByStatus', DWORD),
        ('dwProfileFilter', DWORD),
        ('wFlags', WORD),
    )

class FWEnumFirewallRules2_24Response(NDRCALL):
    structure = (
        ('pdwNumRules', LPDWORD),
        ('ppRules', PFW_RULE2_24_ARRAY),
        ('ErrorCode', DWORD),
    )

RRPC_FWEnumFirewallRules2_24 = FWEnumFirewallRules2_24
RRPC_FWEnumFirewallRules2_24Response = FWEnumFirewallRules2_24Response

# RRPC_FWQueryFirewallRules2_24 (Opnum 73)
class FWQueryFirewallRules2_24(NDRCALL):
    opnum = 73
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
        ('pQuery', PFW_QUERY),
        ('wFlags', WORD),
    )

class FWQueryFirewallRules2_24Response(NDRCALL):
    structure = (
        ('pdwNumRules', LPDWORD),
        ('ppRules', PFW_RULE2_24_ARRAY),
        ('ErrorCode', DWORD),
    )

RRPC_FWQueryFirewallRules2_24 = FWQueryFirewallRules2_24
RRPC_FWQueryFirewallRules2_24Response = FWQueryFirewallRules2_24Response

# RRPC_FWAddFirewallRule2_25 (Opnum 74)
class FWAddFirewallRule2_25(NDRCALL):
    opnum = 74
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
        ('pRule', PFW_RULE2_25),
    )

class FWAddFirewallRule2_25Response(NDRCALL):
    structure = (
        ('pStatus', PFW_RULE_STATUS),
        ('ErrorCode', DWORD),
    )

RRPC_FWAddFirewallRule2_25 = FWAddFirewallRule2_25
RRPC_FWAddFirewallRule2_25Response = FWAddFirewallRule2_25Response

# RRPC_FWSetFirewallRule2_25 (Opnum 75)
class FWSetFirewallRule2_25(NDRCALL):
    opnum = 75
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
        ('pRule', PFW_RULE2_25),
    )

class FWSetFirewallRule2_25Response(NDRCALL):
    structure = (
        ('pStatus', PFW_RULE_STATUS),
        ('ErrorCode', DWORD),
    )

RRPC_FWSetFirewallRule2_25 = FWSetFirewallRule2_25
RRPC_FWSetFirewallRule2_25Response = FWSetFirewallRule2_25Response

# RRPC_FWEnumFirewallRules2_25 (Opnum 76)
class FWEnumFirewallRules2_25(NDRCALL):
    opnum = 76
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
        ('dwFilteredByStatus', DWORD),
        ('dwProfileFilter', DWORD),
        ('wFlags', WORD),
    )

class FWEnumFirewallRules2_25Response(NDRCALL):
    structure = (
        ('pdwNumRules', LPDWORD),
        ('ppRules', PFW_RULE2_25_ARRAY),
        ('ErrorCode', DWORD),
    )

RRPC_FWEnumFirewallRules2_25 = FWEnumFirewallRules2_25
RRPC_FWEnumFirewallRules2_25Response = FWEnumFirewallRules2_25Response

# RRPC_FWQueryFirewallRules2_25 (Opnum 77)
class FWQueryFirewallRules2_25(NDRCALL):
    opnum = 77
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
        ('pQuery', PFW_QUERY),
        ('wFlags', WORD),
    )

class FWQueryFirewallRules2_25Response(NDRCALL):
    structure = (
        ('pdwNumRules', LPDWORD),
        ('ppRules', PFW_RULE2_25_ARRAY),
        ('ErrorCode', DWORD),
    )

RRPC_FWQueryFirewallRules2_25 = FWQueryFirewallRules2_25
RRPC_FWQueryFirewallRules2_25Response = FWQueryFirewallRules2_25Response

# RRPC_FWAddFirewallRule2_26 (Opnum 78)
class FWAddFirewallRule2_26(NDRCALL):
    opnum = 78
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
        ('pRule', PFW_RULE2_26),
    )

class FWAddFirewallRule2_26Response(NDRCALL):
    structure = (
        ('pStatus', PFW_RULE_STATUS),
        ('ErrorCode', DWORD),
    )

RRPC_FWAddFirewallRule2_26 = FWAddFirewallRule2_26
RRPC_FWAddFirewallRule2_26Response = FWAddFirewallRule2_26Response

# RRPC_FWSetFirewallRule2_26 (Opnum 79)
class FWSetFirewallRule2_26(NDRCALL):
    opnum = 79
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
        ('pRule', PFW_RULE2_26),
    )

class FWSetFirewallRule2_26Response(NDRCALL):
    structure = (
        ('pStatus', PFW_RULE_STATUS),
        ('ErrorCode', DWORD),
    )

RRPC_FWSetFirewallRule2_26 = FWSetFirewallRule2_26
RRPC_FWSetFirewallRule2_26Response = FWSetFirewallRule2_26Response

# RRPC_FWEnumFirewallRules2_26 (Opnum 80)
class FWEnumFirewallRules2_26(NDRCALL):
    opnum = 80
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
        ('dwFilteredByStatus', DWORD),
        ('dwProfileFilter', DWORD),
        ('wFlags', WORD),
    )

class FWEnumFirewallRules2_26Response(NDRCALL):
    structure = (
        ('pdwNumRules', LPDWORD),
        ('ppRules', PFW_RULE2_26_ARRAY),
        ('ErrorCode', DWORD),
    )

RRPC_FWEnumFirewallRules2_26 = FWEnumFirewallRules2_26
RRPC_FWEnumFirewallRules2_26Response = FWEnumFirewallRules2_26Response

# RRPC_FWQueryFirewallRules2_26 (Opnum 81)
class FWQueryFirewallRules2_26(NDRCALL):
    opnum = 81
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
        ('pQuery', PFW_QUERY),
        ('wFlags', WORD),
    )

class FWQueryFirewallRules2_26Response(NDRCALL):
    structure = (
        ('pdwNumRules', LPDWORD),
        ('ppRules', PFW_RULE2_26_ARRAY),
        ('ErrorCode', DWORD),
    )

RRPC_FWQueryFirewallRules2_26 = FWQueryFirewallRules2_26
RRPC_FWQueryFirewallRules2_26Response = FWQueryFirewallRules2_26Response

# RRPC_FWAddFirewallRule2_27 (Opnum 82)
class FWAddFirewallRule2_27(NDRCALL):
    opnum = 82
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
        ('pRule', PFW_RULE2_27),
    )

class FWAddFirewallRule2_27Response(NDRCALL):
    structure = (
        ('pStatus', PFW_RULE_STATUS),
        ('ErrorCode', DWORD),
    )

RRPC_FWAddFirewallRule2_27 = FWAddFirewallRule2_27
RRPC_FWAddFirewallRule2_27Response = FWAddFirewallRule2_27Response

# RRPC_FWSetFirewallRule2_27 (Opnum 83)
class FWSetFirewallRule2_27(NDRCALL):
    opnum = 83
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
        ('pRule', PFW_RULE2_27),
    )

class FWSetFirewallRule2_27Response(NDRCALL):
    structure = (
        ('pStatus', PFW_RULE_STATUS),
        ('ErrorCode', DWORD),
    )

RRPC_FWSetFirewallRule2_27 = FWSetFirewallRule2_27
RRPC_FWSetFirewallRule2_27Response = FWSetFirewallRule2_27Response

# RRPC_FWEnumFirewallRules2_27 (Opnum 84)
class FWEnumFirewallRules2_27(NDRCALL):
    opnum = 84
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
        ('dwFilteredByStatus', DWORD),
        ('dwProfileFilter', DWORD),
        ('wFlags', WORD),
    )

class FWEnumFirewallRules2_27Response(NDRCALL):
    structure = (
        ('pdwNumRules', LPDWORD),
        ('ppRules', PFW_RULE2_27_ARRAY),
        ('ErrorCode', DWORD),
    )

RRPC_FWEnumFirewallRules2_27 = FWEnumFirewallRules2_27
RRPC_FWEnumFirewallRules2_27Response = FWEnumFirewallRules2_27Response

# RRPC_FWQueryFirewallRules2_27 (Opnum 85)
class FWQueryFirewallRules2_27(NDRCALL):
    opnum = 85
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
        ('pQuery', PFW_QUERY),
        ('wFlags', WORD),
    )

class FWQueryFirewallRules2_27Response(NDRCALL):
    structure = (
        ('pdwNumRules', LPDWORD),
        ('ppRules', PFW_RULE2_27_ARRAY),
        ('ErrorCode', DWORD),
    )

RRPC_FWQueryFirewallRules2_27 = FWQueryFirewallRules2_27
RRPC_FWQueryFirewallRules2_27Response = FWQueryFirewallRules2_27Response

# RRPC_FWAddFirewallRule2_31 (Opnum 86)
class FWAddFirewallRule2_31(NDRCALL):
    opnum = 86
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
        ('pRule', PFW_RULE2_31),
    )

class FWAddFirewallRule2_31Response(NDRCALL):
    structure = (
        ('pStatus', PFW_RULE_STATUS),
        ('ErrorCode', DWORD),
    )

RRPC_FWAddFirewallRule2_31 = FWAddFirewallRule2_31
RRPC_FWAddFirewallRule2_31Response = FWAddFirewallRule2_31Response

# RRPC_FWSetFirewallRule2_31 (Opnum 87)
class FWSetFirewallRule2_31(NDRCALL):
    opnum = 87
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
        ('pRule', PFW_RULE2_31),
    )

class FWSetFirewallRule2_31Response(NDRCALL):
    structure = (
        ('pStatus', PFW_RULE_STATUS),
        ('ErrorCode', DWORD),
    )

RRPC_FWSetFirewallRule2_31 = FWSetFirewallRule2_31
RRPC_FWSetFirewallRule2_31Response = FWSetFirewallRule2_31Response

# RRPC_FWEnumFirewallRules2_31 (Opnum 88)
class FWEnumFirewallRules2_31(NDRCALL):
    opnum = 88
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
        ('dwFilteredByStatus', DWORD),
        ('dwProfileFilter', DWORD),
        ('wFlags', WORD),
    )

class FWEnumFirewallRules2_31Response(NDRCALL):
    structure = (
        ('pdwNumRules', LPDWORD),
        ('ppRules', PFW_RULE2_31_ARRAY),
        ('ErrorCode', DWORD),
    )

RRPC_FWEnumFirewallRules2_31 = FWEnumFirewallRules2_31
RRPC_FWEnumFirewallRules2_31Response = FWEnumFirewallRules2_31Response

# RRPC_FWQueryFirewallRules2_31 (Opnum 89)
class FWQueryFirewallRules2_31(NDRCALL):
    opnum = 89
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
        ('pQuery', PFW_QUERY),
        ('wFlags', WORD),
    )

class FWQueryFirewallRules2_31Response(NDRCALL):
    structure = (
        ('pdwNumRules', LPDWORD),
        ('ppRules', PFW_RULE2_31_ARRAY),
        ('ErrorCode', DWORD),
    )

RRPC_FWQueryFirewallRules2_31 = FWQueryFirewallRules2_31
RRPC_FWQueryFirewallRules2_31Response = FWQueryFirewallRules2_31Response

# RRPC_FWAddFirewallRule2_33 (Opnum 90)
class FWAddFirewallRule2_33(NDRCALL):
    opnum = 90
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
        ('pRule', PFW_RULE),
    )

class FWAddFirewallRule2_33Response(NDRCALL):
    structure = (
        ('pStatus', PFW_RULE_STATUS),
        ('ErrorCode', DWORD),
    )

RRPC_FWAddFirewallRule2_33 = FWAddFirewallRule2_33
RRPC_FWAddFirewallRule2_33Response = FWAddFirewallRule2_33Response

# RRPC_FWSetFirewallRule2_33 (Opnum 91)
class FWSetFirewallRule2_33(NDRCALL):
    opnum = 91
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
        ('pRule', PFW_RULE),
    )

class FWSetFirewallRule2_33Response(NDRCALL):
    structure = (
        ('pStatus', PFW_RULE_STATUS),
        ('ErrorCode', DWORD),
    )

RRPC_FWSetFirewallRule2_33 = FWSetFirewallRule2_33
RRPC_FWSetFirewallRule2_33Response = FWSetFirewallRule2_33Response

# RRPC_FWEnumFirewallRules2_33 (Opnum 92)
class FWEnumFirewallRules2_33(NDRCALL):
    opnum = 92
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
        ('dwFilteredByStatus', DWORD),
        ('dwProfileFilter', DWORD),
        ('wFlags', WORD),
    )

class FWEnumFirewallRules2_33Response(NDRCALL):
    structure = (
        ('pdwNumRules', LPDWORD),
        ('ppRules', PFW_RULE_ARRAY),
        ('ErrorCode', DWORD),
    )

RRPC_FWEnumFirewallRules2_33 = FWEnumFirewallRules2_33
RRPC_FWEnumFirewallRules2_33Response = FWEnumFirewallRules2_33Response

# RRPC_FWQueryFirewallRules2_33 (Opnum 93)
class FWQueryFirewallRules2_33(NDRCALL):
    opnum = 93
    structure = (
        ('hPolicyStore', FW_POLICY_STORE_HANDLE),
        ('pQuery', PFW_QUERY),
        ('wFlags', WORD),
    )

class FWQueryFirewallRules2_33Response(NDRCALL):
    structure = (
        ('pdwNumRules', LPDWORD),
        ('ppRules', PFW_RULE_ARRAY),
        ('ErrorCode', DWORD),
    )

RRPC_FWQueryFirewallRules2_33 = FWQueryFirewallRules2_33
RRPC_FWQueryFirewallRules2_33Response = FWQueryFirewallRules2_33Response

################################################################################
# OPNUMs and their corresponding structures
################################################################################

OPNUMS = {
    0: (FWOpenPolicyStore, FWOpenPolicyStoreResponse),
    1: (FWClosePolicyStore, FWClosePolicyStoreResponse),
    2: (FWRestoreDefaults, FWRestoreDefaultsResponse),
    3: (FWGetGlobalConfig, FWGetGlobalConfigResponse),
    4: (FWSetGlobalConfig, FWSetGlobalConfigResponse),
    5: (FWAddFirewallRule, FWAddFirewallRuleResponse),
    6: (FWSetFirewallRule, FWSetFirewallRuleResponse),
    7: (FWDeleteFirewallRule, FWDeleteFirewallRuleResponse),
    8: (FWDeleteAllFirewallRules, FWDeleteAllFirewallRulesResponse),
    9: (FWEnumFirewallRules, FWEnumFirewallRulesResponse),
    10: (FWGetConfig, FWGetConfigResponse),
    11: (FWSetConfig, FWSetConfigResponse),
    12: (FWAddConnectionSecurityRule, FWAddConnectionSecurityRuleResponse),
    13: (FWSetConnectionSecurityRule, FWSetConnectionSecurityRuleResponse),
    14: (FWDeleteConnectionSecurityRule, FWDeleteConnectionSecurityRuleResponse),
    15: (FWDeleteAllConnectionSecurityRules, FWDeleteAllConnectionSecurityRulesResponse),
    16: (FWEnumConnectionSecurityRules, FWEnumConnectionSecurityRulesResponse),
    17: (FWAddAuthenticationSet, FWAddAuthenticationSetResponse),
    18: (FWSetAuthenticationSet, FWSetAuthenticationSetResponse),
    19: (FWDeleteAuthenticationSet, FWDeleteAuthenticationSetResponse),
    20: (FWDeleteAllAuthenticationSets, FWDeleteAllAuthenticationSetsResponse),
    21: (FWEnumAuthenticationSets, FWEnumAuthenticationSetsResponse),
    22: (FWAddCryptoSet, FWAddCryptoSetResponse),
    23: (FWSetCryptoSet, FWSetCryptoSetResponse),
    24: (FWDeleteCryptoSet, FWDeleteCryptoSetResponse),
    25: (FWDeleteAllCryptoSets, FWDeleteAllCryptoSetsResponse),
    26: (FWEnumCryptoSets, FWEnumCryptoSetsResponse),
    27: (FWEnumPhase1SAs, FWEnumPhase1SAsResponse),
    28: (FWEnumPhase2SAs, FWEnumPhase2SAsResponse),
    29: (FWDeletePhase1SAs, FWDeletePhase1SAsResponse),
    30: (FWDeletePhase2SAs, FWDeletePhase2SAsResponse),
    31: (FWEnumProducts, FWEnumProductsResponse),
    32: (FWAddMainModeRule, FWAddMainModeRuleResponse),
    33: (FWSetMainModeRule, FWSetMainModeRuleResponse),
    34: (FWDeleteMainModeRule, FWDeleteMainModeRuleResponse),
    35: (FWDeleteAllMainModeRules, FWDeleteAllMainModeRulesResponse),
    36: (FWEnumMainModeRules, FWEnumMainModeRulesResponse),
    37: (FWQueryFirewallRules, FWQueryFirewallRulesResponse),
    38: (FWQueryConnectionSecurityRules2_10, FWQueryConnectionSecurityRules2_10Response),
    39: (FWQueryMainModeRules, FWQueryMainModeRulesResponse),
    40: (FWQueryAuthenticationSets, FWQueryAuthenticationSetsResponse),
    41: (FWQueryCryptoSets, FWQueryCryptoSetsResponse),
    42: (FWEnumNetworks, FWEnumNetworksResponse),
    43: (FWEnumAdapters, FWEnumAdaptersResponse),
    44: (FWGetGlobalConfig2_10, FWGetGlobalConfig2_10Response),
    45: (FWGetConfig2_10, FWGetConfig2_10Response),
    46: (FWAddFirewallRule2_10, FWAddFirewallRule2_10Response),
    47: (FWSetFirewallRule2_10, FWSetFirewallRule2_10Response),
    48: (FWEnumFirewallRules2_10, FWEnumFirewallRules2_10Response),
    49: (FWAddConnectionSecurityRule2_10, FWAddConnectionSecurityRule2_10Response),
    50: (FWSetConnectionSecurityRule2_10, FWSetConnectionSecurityRule2_10Response),
    51: (FWEnumConnectionSecurityRules2_10, FWEnumConnectionSecurityRules2_10Response),
    52: (FWAddAuthenticationSet2_10, FWAddAuthenticationSet2_10Response),
    53: (FWSetAuthenticationSet2_10, FWSetAuthenticationSet2_10Response),
    54: (FWEnumAuthenticationSets2_10, FWEnumAuthenticationSets2_10Response),
    55: (FWAddCryptoSet2_10, FWAddCryptoSet2_10Response),
    56: (FWSetCryptoSet2_10, FWSetCryptoSet2_10Response),
    57: (FWEnumCryptoSets2_10, FWEnumCryptoSets2_10Response),
    58: (FWAddConnectionSecurityRule2_20, FWAddConnectionSecurityRule2_20Response),
    59: (FWSetConnectionSecurityRule2_20, FWSetConnectionSecurityRule2_20Response),
    60: (FWEnumConnectionSecurityRules2_20, FWEnumConnectionSecurityRules2_20Response),
    61: (FWQueryConnectionSecurityRules2_20, FWQueryConnectionSecurityRules2_20Response),
    62: (FWAddAuthenticationSet2_20, FWAddAuthenticationSet2_20Response),
    63: (FWSetAuthenticationSet2_20, FWSetAuthenticationSet2_20Response),
    64: (FWEnumAuthenticationSets2_20, FWEnumAuthenticationSets2_20Response),
    65: (FWQueryAuthenticationSets2_20, FWQueryAuthenticationSets2_20Response),
    66: (FWAddFirewallRule2_20, FWAddFirewallRule2_20Response),
    67: (FWSetFirewallRule2_20, FWSetFirewallRule2_20Response),
    68: (FWEnumFirewallRules2_20, FWEnumFirewallRules2_20Response),
    69: (FWQueryFirewallRules2_20, FWQueryFirewallRules2_20Response),
    70: (FWAddFirewallRule2_24, FWAddFirewallRule2_24Response),
    71: (FWSetFirewallRule2_24, FWSetFirewallRule2_24Response),
    72: (FWEnumFirewallRules2_24, FWEnumFirewallRules2_24Response),
    73: (FWQueryFirewallRules2_24, FWQueryFirewallRules2_24Response),
    74: (FWAddFirewallRule2_25, FWAddFirewallRule2_25Response),
    75: (FWSetFirewallRule2_25, FWSetFirewallRule2_25Response),
    76: (FWEnumFirewallRules2_25, FWEnumFirewallRules2_25Response),
    77: (FWQueryFirewallRules2_25, FWQueryFirewallRules2_25Response),
    78: (FWAddFirewallRule2_26, FWAddFirewallRule2_26Response),
    79: (FWSetFirewallRule2_26, FWSetFirewallRule2_26Response),
    80: (FWEnumFirewallRules2_26, FWEnumFirewallRules2_26Response),
    81: (FWQueryFirewallRules2_26, FWQueryFirewallRules2_26Response),
    82: (FWAddFirewallRule2_27, FWAddFirewallRule2_27Response),
    83: (FWSetFirewallRule2_27, FWSetFirewallRule2_27Response),
    84: (FWEnumFirewallRules2_27, FWEnumFirewallRules2_27Response),
    85: (FWQueryFirewallRules2_27, FWQueryFirewallRules2_27Response),
    86: (FWAddFirewallRule2_31, FWAddFirewallRule2_31Response),
    87: (FWSetFirewallRule2_31, FWSetFirewallRule2_31Response),
    88: (FWEnumFirewallRules2_31, FWEnumFirewallRules2_31Response),
    89: (FWQueryFirewallRules2_31, FWQueryFirewallRules2_31Response),
    90: (FWAddFirewallRule2_33, FWAddFirewallRule2_33Response),
    91: (FWSetFirewallRule2_33, FWSetFirewallRule2_33Response),
    92: (FWEnumFirewallRules2_33, FWEnumFirewallRules2_33Response),
    93: (FWQueryFirewallRules2_33, FWQueryFirewallRules2_33Response),
}

################################################################################
# HELPER FUNCTIONS
################################################################################

def hFWOpenPolicyStore(dce, binaryVersion=FW_BINARY_VERSION_2_0,
                       storeType=FW_STORE_TYPE.FW_STORE_TYPE_LOCAL,
                       accessRight=FW_POLICY_ACCESS_RIGHT.FW_POLICY_ACCESS_RIGHT_READ,
                       dwFlags=FW_POLICY_STORE_FLAGS.FW_POLICY_STORE_FLAGS_NONE):
    request = FWOpenPolicyStore()
    request['BinaryVersion'] = binaryVersion
    request['StoreType'] = storeType
    request['AccessRight'] = accessRight
    request['dwFlags'] = dwFlags
    return dce.request(request)

def hFWClosePolicyStore(dce, phPolicyStore):
    request = FWClosePolicyStore()
    request['phPolicyStore'] = phPolicyStore
    return dce.request(request)

def hFWRestoreDefaults(dce):
    request = FWRestoreDefaults()
    return dce.request(request)

def hFWGetGlobalConfig(dce, BinaryVersion, StoreType, configID, dwFlags, pBuffer, cbData, pcbTransmittedLen):
    request = FWGetGlobalConfig()
    request['BinaryVersion'] = BinaryVersion
    request['StoreType'] = StoreType
    request['configID'] = configID
    request['dwFlags'] = dwFlags
    request['pBuffer'] = pBuffer
    request['cbData'] = cbData
    request['pcbTransmittedLen'] = pcbTransmittedLen
    return dce.request(request)

def hFWSetGlobalConfig(dce, BinaryVersion, StoreType, configID, lpBuffer, dwBufSize):
    request = FWSetGlobalConfig()
    request['BinaryVersion'] = BinaryVersion
    request['StoreType'] = StoreType
    request['configID'] = configID
    request['lpBuffer'] = lpBuffer
    request['dwBufSize'] = dwBufSize
    return dce.request(request)

def hFWAddFirewallRule(dce, hPolicyStore, pRule):
    request = FWAddFirewallRule()
    request['hPolicyStore'] = hPolicyStore
    request['pRule'] = pRule
    return dce.request(request)

def hFWSetFirewallRule(dce, hPolicyStore, pRule):
    request = FWSetFirewallRule()
    request['hPolicyStore'] = hPolicyStore
    request['pRule'] = pRule
    return dce.request(request)

def hFWDeleteFirewallRule(dce, hPolicyStore, wszRuleID):
    request = FWDeleteFirewallRule()
    request['hPolicyStore'] = hPolicyStore
    request['wszRuleID'] = wszRuleID
    return dce.request(request)

def hFWDeleteAllFirewallRules(dce, hPolicyStore):
    request = FWDeleteAllFirewallRules()
    request['hPolicyStore'] = hPolicyStore
    return dce.request(request)

def hFWEnumFirewallRules(dce, hPolicyStore, dwFilteredByStatus, dwProfileFilter, wFlags):
    request = FWEnumFirewallRules()
    request['hPolicyStore'] = hPolicyStore
    request['dwFilteredByStatus'] = dwFilteredByStatus
    request['dwProfileFilter'] = dwProfileFilter
    request['wFlags'] = wFlags
    return dce.request(request)

def hFWGetConfig(dce, hPolicyStore, configID, Profile, dwFlags, pBuffer, cbData, pcbTransmittedLen):
    request = FWGetConfig()
    request['hPolicyStore'] = hPolicyStore
    request['configID'] = configID
    request['Profile'] = Profile
    request['dwFlags'] = dwFlags
    request['pBuffer'] = pBuffer
    request['cbData'] = cbData
    request['pcbTransmittedLen'] = pcbTransmittedLen
    return dce.request(request)

def hFWSetConfig(dce, hPolicyStore, configID, Profile, pConfig, dwBufSize):
    request = FWSetConfig()
    request['hPolicyStore'] = hPolicyStore
    request['configID'] = configID
    request['Profile'] = Profile
    request['pConfig'] = pConfig
    request['dwBufSize'] = dwBufSize
    return dce.request(request)

def hFWAddConnectionSecurityRule(dce, hPolicyStore, pRule):
    request = FWAddConnectionSecurityRule()
    request['hPolicyStore'] = hPolicyStore
    request['pRule'] = pRule
    return dce.request(request)

def hFWSetConnectionSecurityRule(dce, hPolicyStore, pRule):
    request = FWSetConnectionSecurityRule()
    request['hPolicyStore'] = hPolicyStore
    request['pRule'] = pRule
    return dce.request(request)

def hFWDeleteConnectionSecurityRule(dce, hPolicyStore, pRuleId):
    request = FWDeleteConnectionSecurityRule()
    request['hPolicyStore'] = hPolicyStore
    request['pRuleId'] = pRuleId
    return dce.request(request)

def hFWDeleteAllConnectionSecurityRules(dce, hPolicyStore):
    request = FWDeleteAllConnectionSecurityRules()
    request['hPolicyStore'] = hPolicyStore
    return dce.request(request)

def hFWEnumConnectionSecurityRules(dce, hPolicyStore, dwFilteredByStatus, dwProfileFilter, wFlags):
    request = FWEnumConnectionSecurityRules()
    request['hPolicyStore'] = hPolicyStore
    request['dwFilteredByStatus'] = dwFilteredByStatus
    request['dwProfileFilter'] = dwProfileFilter
    request['wFlags'] = wFlags
    return dce.request(request)

def hFWAddAuthenticationSet(dce, hPolicyStore, pAuth):
    request = FWAddAuthenticationSet()
    request['hPolicyStore'] = hPolicyStore
    request['pAuth'] = pAuth
    return dce.request(request)

def hFWSetAuthenticationSet(dce, hPolicyStore, pAuth):
    request = FWSetAuthenticationSet()
    request['hPolicyStore'] = hPolicyStore
    request['pAuth'] = pAuth
    return dce.request(request)

def hFWDeleteAuthenticationSet(dce, hPolicyStore, IpSecPhase, wszSetId):
    request = FWDeleteAuthenticationSet()
    request['hPolicyStore'] = hPolicyStore
    request['IpSecPhase'] = IpSecPhase
    request['wszSetId'] = wszSetId
    return dce.request(request)

def hFWDeleteAllAuthenticationSets(dce, hPolicyStore, IpSecPhase):
    request = FWDeleteAllAuthenticationSets()
    request['hPolicyStore'] = hPolicyStore
    request['IpSecPhase'] = IpSecPhase
    return dce.request(request)

def hFWEnumAuthenticationSets(dce, hPolicyStore, IpSecPhase, dwFilteredByStatus, wFlags):
    request = FWEnumAuthenticationSets()
    request['hPolicyStore'] = hPolicyStore
    request['IpSecPhase'] = IpSecPhase
    request['dwFilteredByStatus'] = dwFilteredByStatus
    request['wFlags'] = wFlags
    return dce.request(request)

def hFWAddCryptoSet(dce, hPolicyStore, pCrypto):
    request = FWAddCryptoSet()
    request['hPolicyStore'] = hPolicyStore
    request['pCrypto'] = pCrypto
    return dce.request(request)

def hFWSetCryptoSet(dce, hPolicyStore, pCrypto):
    request = FWSetCryptoSet()
    request['hPolicyStore'] = hPolicyStore
    request['pCrypto'] = pCrypto
    return dce.request(request)

def hFWDeleteCryptoSet(dce, hPolicyStore, IpSecPhase, wszSetId):
    request = FWDeleteCryptoSet()
    request['hPolicyStore'] = hPolicyStore
    request['IpSecPhase'] = IpSecPhase
    request['wszSetId'] = wszSetId
    return dce.request(request)

def hFWDeleteAllCryptoSets(dce, hPolicyStore, IpSecPhase):
    request = FWDeleteAllCryptoSets()
    request['hPolicyStore'] = hPolicyStore
    request['IpSecPhase'] = IpSecPhase
    return dce.request(request)

def hFWEnumCryptoSets(dce, hPolicyStore, IpSecPhase, dwFilteredByStatus, wFlags):
    request = FWEnumCryptoSets()
    request['hPolicyStore'] = hPolicyStore
    request['IpSecPhase'] = IpSecPhase
    request['dwFilteredByStatus'] = dwFilteredByStatus
    request['wFlags'] = wFlags
    return dce.request(request)

def hFWEnumPhase1SAs(dce, hPolicyStore, pEndpoints):
    request = FWEnumPhase1SAs()
    request['hPolicyStore'] = hPolicyStore
    request['pEndpoints'] = pEndpoints
    return dce.request(request)

def hFWEnumPhase2SAs(dce, hPolicyStore, pEndpoints):
    request = FWEnumPhase2SAs()
    request['hPolicyStore'] = hPolicyStore
    request['pEndpoints'] = pEndpoints
    return dce.request(request)

def hFWDeletePhase1SAs(dce, hPolicyStore, pEndpoints):
    request = FWDeletePhase1SAs()
    request['hPolicyStore'] = hPolicyStore
    request['pEndpoints'] = pEndpoints
    return dce.request(request)

def hFWDeletePhase2SAs(dce, hPolicyStore, pEndpoints):
    request = FWDeletePhase2SAs()
    request['hPolicyStore'] = hPolicyStore
    request['pEndpoints'] = pEndpoints
    return dce.request(request)

def hFWEnumProducts(dce, hPolicyStore):
    request = FWEnumProducts()
    request['hPolicyStore'] = hPolicyStore
    return dce.request(request)

def hFWAddMainModeRule(dce, hPolicyStore, pMMRule):
    request = FWAddMainModeRule()
    request['hPolicyStore'] = hPolicyStore
    request['pMMRule'] = pMMRule
    return dce.request(request)

def hFWSetMainModeRule(dce, hPolicyStore, pMMRule):
    request = FWSetMainModeRule()
    request['hPolicyStore'] = hPolicyStore
    request['pMMRule'] = pMMRule
    return dce.request(request)

def hFWDeleteMainModeRule(dce, hPolicyStore, pRuleId):
    request = FWDeleteMainModeRule()
    request['hPolicyStore'] = hPolicyStore
    request['pRuleId'] = pRuleId
    return dce.request(request)

def hFWDeleteAllMainModeRules(dce, hPolicyStore):
    request = FWDeleteAllMainModeRules()
    request['hPolicyStore'] = hPolicyStore
    return dce.request(request)

def hFWEnumMainModeRules(dce, hPolicyStore, dwFilteredByStatus, dwProfileFilter, wFlags):
    request = FWEnumMainModeRules()
    request['hPolicyStore'] = hPolicyStore
    request['dwFilteredByStatus'] = dwFilteredByStatus
    request['dwProfileFilter'] = dwProfileFilter
    request['wFlags'] = wFlags
    return dce.request(request)

def hFWQueryFirewallRules(dce, hPolicyStore, pQuery, wFlags):
    request = FWQueryFirewallRules()
    request['hPolicyStore'] = hPolicyStore
    request['pQuery'] = pQuery
    request['wFlags'] = wFlags
    return dce.request(request)

def hFWQueryConnectionSecurityRules2_10(dce, hPolicyStore, pQuery, wFlags):
    request = FWQueryConnectionSecurityRules2_10()
    request['hPolicyStore'] = hPolicyStore
    request['pQuery'] = pQuery
    request['wFlags'] = wFlags
    return dce.request(request)

def hFWQueryMainModeRules(dce, hPolicyStore, pQuery, wFlags):
    request = FWQueryMainModeRules()
    request['hPolicyStore'] = hPolicyStore
    request['pQuery'] = pQuery
    request['wFlags'] = wFlags
    return dce.request(request)

def hFWQueryAuthenticationSets(dce, hPolicyStore, IPsecPhase, pQuery, wFlags):
    request = FWQueryAuthenticationSets()
    request['hPolicyStore'] = hPolicyStore
    request['IPsecPhase'] = IPsecPhase
    request['pQuery'] = pQuery
    request['wFlags'] = wFlags
    return dce.request(request)

def hFWQueryCryptoSets(dce, hPolicyStore, IPsecPhase, pQuery, wFlags):
    request = FWQueryCryptoSets()
    request['hPolicyStore'] = hPolicyStore
    request['IPsecPhase'] = IPsecPhase
    request['pQuery'] = pQuery
    request['wFlags'] = wFlags
    return dce.request(request)

def hFWEnumNetworks(dce, hPolicyStore):
    request = FWEnumNetworks()
    request['hPolicyStore'] = hPolicyStore
    return dce.request(request)

def hFWEnumAdapters(dce, hPolicyStore):
    request = FWEnumAdapters()
    request['hPolicyStore'] = hPolicyStore
    return dce.request(request)

def hFWGetGlobalConfig2_10(dce, BinaryVersion, StoreType, configID, dwFlags, pBuffer, cbData, pcbTransmittedLen):
    request = FWGetGlobalConfig2_10()
    request['BinaryVersion'] = BinaryVersion
    request['StoreType'] = StoreType
    request['configID'] = configID
    request['dwFlags'] = dwFlags
    request['pBuffer'] = pBuffer
    request['cbData'] = cbData
    request['pcbTransmittedLen'] = pcbTransmittedLen
    return dce.request(request)

def hFWGetConfig2_10(dce, hPolicyStore, configID, Profile, dwFlags, pBuffer, cbData, pcbTransmittedLen):
    request = FWGetConfig2_10()
    request['hPolicyStore'] = hPolicyStore
    request['configID'] = configID
    request['Profile'] = Profile
    request['dwFlags'] = dwFlags
    request['pBuffer'] = pBuffer
    request['cbData'] = cbData
    request['pcbTransmittedLen'] = pcbTransmittedLen
    return dce.request(request)

def hFWAddFirewallRule2_10(dce, hPolicyStore, pRule):
    request = FWAddFirewallRule2_10()
    request['hPolicyStore'] = hPolicyStore
    request['pRule'] = pRule
    return dce.request(request)

def hFWSetFirewallRule2_10(dce, hPolicyStore, pRule):
    request = FWSetFirewallRule2_10()
    request['hPolicyStore'] = hPolicyStore
    request['pRule'] = pRule
    return dce.request(request)

def hFWEnumFirewallRules2_10(dce, hPolicyStore, dwFilteredByStatus, dwProfileFilter, wFlags):
    request = FWEnumFirewallRules2_10()
    request['hPolicyStore'] = hPolicyStore
    request['dwFilteredByStatus'] = dwFilteredByStatus
    request['dwProfileFilter'] = dwProfileFilter
    request['wFlags'] = wFlags
    return dce.request(request)

def hFWAddConnectionSecurityRule2_10(dce, hPolicyStore, pRule):
    request = FWAddConnectionSecurityRule2_10()
    request['hPolicyStore'] = hPolicyStore
    request['pRule'] = pRule
    return dce.request(request)

def hFWSetConnectionSecurityRule2_10(dce, hPolicyStore, pRule):
    request = FWSetConnectionSecurityRule2_10()
    request['hPolicyStore'] = hPolicyStore
    request['pRule'] = pRule
    return dce.request(request)

def hFWEnumConnectionSecurityRules2_10(dce, hPolicyStore, dwFilteredByStatus, dwProfileFilter, wFlags):
    request = FWEnumConnectionSecurityRules2_10()
    request['hPolicyStore'] = hPolicyStore
    request['dwFilteredByStatus'] = dwFilteredByStatus
    request['dwProfileFilter'] = dwProfileFilter
    request['wFlags'] = wFlags
    return dce.request(request)

def hFWAddAuthenticationSet2_10(dce, hPolicyStore, pAuth):
    request = FWAddAuthenticationSet2_10()
    request['hPolicyStore'] = hPolicyStore
    request['pAuth'] = pAuth
    return dce.request(request)

def hFWSetAuthenticationSet2_10(dce, hPolicyStore, pAuth):
    request = FWSetAuthenticationSet2_10()
    request['hPolicyStore'] = hPolicyStore
    request['pAuth'] = pAuth
    return dce.request(request)

def hFWEnumAuthenticationSets2_10(dce, hPolicyStore, IpSecPhase, dwFilteredByStatus, wFlags):
    request = FWEnumAuthenticationSets2_10()
    request['hPolicyStore'] = hPolicyStore
    request['IpSecPhase'] = IpSecPhase
    request['dwFilteredByStatus'] = dwFilteredByStatus
    request['wFlags'] = wFlags
    return dce.request(request)

def hFWAddCryptoSet2_10(dce, hPolicyStore, pCrypto):
    request = FWAddCryptoSet2_10()
    request['hPolicyStore'] = hPolicyStore
    request['pCrypto'] = pCrypto
    return dce.request(request)

def hFWSetCryptoSet2_10(dce, hPolicyStore, pCrypto):
    request = FWSetCryptoSet2_10()
    request['hPolicyStore'] = hPolicyStore
    request['pCrypto'] = pCrypto
    return dce.request(request)

def hFWEnumCryptoSets2_10(dce, hPolicyStore, IpSecPhase, dwFilteredByStatus, wFlags):
    request = FWEnumCryptoSets2_10()
    request['hPolicyStore'] = hPolicyStore
    request['IpSecPhase'] = IpSecPhase
    request['dwFilteredByStatus'] = dwFilteredByStatus
    request['wFlags'] = wFlags
    return dce.request(request)

def hFWAddConnectionSecurityRule2_20(dce, hPolicyStore, pRule):
    request = FWAddConnectionSecurityRule2_20()
    request['hPolicyStore'] = hPolicyStore
    request['pRule'] = pRule
    return dce.request(request)

def hFWSetConnectionSecurityRule2_20(dce, hPolicyStore, pRule):
    request = FWSetConnectionSecurityRule2_20()
    request['hPolicyStore'] = hPolicyStore
    request['pRule'] = pRule
    return dce.request(request)

def hFWEnumConnectionSecurityRules2_20(dce, hPolicyStore, dwFilteredByStatus, dwProfileFilter, wFlags):
    request = FWEnumConnectionSecurityRules2_20()
    request['hPolicyStore'] = hPolicyStore
    request['dwFilteredByStatus'] = dwFilteredByStatus
    request['dwProfileFilter'] = dwProfileFilter
    request['wFlags'] = wFlags
    return dce.request(request)

def hFWQueryConnectionSecurityRules2_20(dce, hPolicyStore, pQuery, wFlags):
    request = FWQueryConnectionSecurityRules2_20()
    request['hPolicyStore'] = hPolicyStore
    request['pQuery'] = pQuery
    request['wFlags'] = wFlags
    return dce.request(request)

def hFWAddAuthenticationSet2_20(dce, hPolicyStore, pAuth):
    request = FWAddAuthenticationSet2_20()
    request['hPolicyStore'] = hPolicyStore
    request['pAuth'] = pAuth
    return dce.request(request)

def hFWSetAuthenticationSet2_20(dce, hPolicyStore, pAuth):
    request = FWSetAuthenticationSet2_20()
    request['hPolicyStore'] = hPolicyStore
    request['pAuth'] = pAuth
    return dce.request(request)

def hFWEnumAuthenticationSets2_20(dce, hPolicyStore, IpSecPhase, dwFilteredByStatus, wFlags):
    request = FWEnumAuthenticationSets2_20()
    request['hPolicyStore'] = hPolicyStore
    request['IpSecPhase'] = IpSecPhase
    request['dwFilteredByStatus'] = dwFilteredByStatus
    request['wFlags'] = wFlags
    return dce.request(request)

def hFWQueryAuthenticationSets2_20(dce, hPolicyStore, IPsecPhase, pQuery, wFlags):
    request = FWQueryAuthenticationSets2_20()
    request['hPolicyStore'] = hPolicyStore
    request['IPsecPhase'] = IPsecPhase
    request['pQuery'] = pQuery
    request['wFlags'] = wFlags
    return dce.request(request)

def hFWAddFirewallRule2_20(dce, hPolicyStore, pRule):
    request = FWAddFirewallRule2_20()
    request['hPolicyStore'] = hPolicyStore
    request['pRule'] = pRule
    return dce.request(request)

def hFWSetFirewallRule2_20(dce, hPolicyStore, pRule):
    request = FWSetFirewallRule2_20()
    request['hPolicyStore'] = hPolicyStore
    request['pRule'] = pRule
    return dce.request(request)

def hFWEnumFirewallRules2_20(dce, hPolicyStore, dwFilteredByStatus, dwProfileFilter, wFlags):
    request = FWEnumFirewallRules2_20()
    request['hPolicyStore'] = hPolicyStore
    request['dwFilteredByStatus'] = dwFilteredByStatus
    request['dwProfileFilter'] = dwProfileFilter
    request['wFlags'] = wFlags
    return dce.request(request)

def hFWQueryFirewallRules2_20(dce, hPolicyStore, pQuery, wFlags):
    request = FWQueryFirewallRules2_20()
    request['hPolicyStore'] = hPolicyStore
    request['pQuery'] = pQuery
    request['wFlags'] = wFlags
    return dce.request(request)

def hFWAddFirewallRule2_24(dce, hPolicyStore, pRule):
    request = FWAddFirewallRule2_24()
    request['hPolicyStore'] = hPolicyStore
    request['pRule'] = pRule
    return dce.request(request)

def hFWSetFirewallRule2_24(dce, hPolicyStore, pRule):
    request = FWSetFirewallRule2_24()
    request['hPolicyStore'] = hPolicyStore
    request['pRule'] = pRule
    return dce.request(request)

def hFWEnumFirewallRules2_24(dce, hPolicyStore, dwFilteredByStatus, dwProfileFilter, wFlags):
    request = FWEnumFirewallRules2_24()
    request['hPolicyStore'] = hPolicyStore
    request['dwFilteredByStatus'] = dwFilteredByStatus
    request['dwProfileFilter'] = dwProfileFilter
    request['wFlags'] = wFlags
    return dce.request(request)

def hFWQueryFirewallRules2_24(dce, hPolicyStore, pQuery, wFlags):
    request = FWQueryFirewallRules2_24()
    request['hPolicyStore'] = hPolicyStore
    request['pQuery'] = pQuery
    request['wFlags'] = wFlags
    return dce.request(request)

def hFWAddFirewallRule2_25(dce, hPolicyStore, pRule):
    request = FWAddFirewallRule2_25()
    request['hPolicyStore'] = hPolicyStore
    request['pRule'] = pRule
    return dce.request(request)

def hFWSetFirewallRule2_25(dce, hPolicyStore, pRule):
    request = FWSetFirewallRule2_25()
    request['hPolicyStore'] = hPolicyStore
    request['pRule'] = pRule
    return dce.request(request)

def hFWEnumFirewallRules2_25(dce, hPolicyStore, dwFilteredByStatus, dwProfileFilter, wFlags):
    request = FWEnumFirewallRules2_25()
    request['hPolicyStore'] = hPolicyStore
    request['dwFilteredByStatus'] = dwFilteredByStatus
    request['dwProfileFilter'] = dwProfileFilter
    request['wFlags'] = wFlags
    return dce.request(request)

def hFWQueryFirewallRules2_25(dce, hPolicyStore, pQuery, wFlags):
    request = FWQueryFirewallRules2_25()
    request['hPolicyStore'] = hPolicyStore
    request['pQuery'] = pQuery
    request['wFlags'] = wFlags
    return dce.request(request)

def hFWAddFirewallRule2_26(dce, hPolicyStore, pRule):
    request = FWAddFirewallRule2_26()
    request['hPolicyStore'] = hPolicyStore
    request['pRule'] = pRule
    return dce.request(request)

def hFWSetFirewallRule2_26(dce, hPolicyStore, pRule):
    request = FWSetFirewallRule2_26()
    request['hPolicyStore'] = hPolicyStore
    request['pRule'] = pRule
    return dce.request(request)

def hFWEnumFirewallRules2_26(dce, hPolicyStore, dwFilteredByStatus, dwProfileFilter, wFlags):
    request = FWEnumFirewallRules2_26()
    request['hPolicyStore'] = hPolicyStore
    request['dwFilteredByStatus'] = dwFilteredByStatus
    request['dwProfileFilter'] = dwProfileFilter
    request['wFlags'] = wFlags
    return dce.request(request)

def hFWQueryFirewallRules2_26(dce, hPolicyStore, pQuery, wFlags):
    request = FWQueryFirewallRules2_26()
    request['hPolicyStore'] = hPolicyStore
    request['pQuery'] = pQuery
    request['wFlags'] = wFlags
    return dce.request(request)

def hFWAddFirewallRule2_27(dce, hPolicyStore, pRule):
    request = FWAddFirewallRule2_27()
    request['hPolicyStore'] = hPolicyStore
    request['pRule'] = pRule
    return dce.request(request)

def hFWSetFirewallRule2_27(dce, hPolicyStore, pRule):
    request = FWSetFirewallRule2_27()
    request['hPolicyStore'] = hPolicyStore
    request['pRule'] = pRule
    return dce.request(request)

def hFWEnumFirewallRules2_27(dce, hPolicyStore, dwFilteredByStatus, dwProfileFilter, wFlags):
    request = FWEnumFirewallRules2_27()
    request['hPolicyStore'] = hPolicyStore
    request['dwFilteredByStatus'] = dwFilteredByStatus
    request['dwProfileFilter'] = dwProfileFilter
    request['wFlags'] = wFlags
    return dce.request(request)

def hFWQueryFirewallRules2_27(dce, hPolicyStore, pQuery, wFlags):
    request = FWQueryFirewallRules2_27()
    request['hPolicyStore'] = hPolicyStore
    request['pQuery'] = pQuery
    request['wFlags'] = wFlags
    return dce.request(request)

def hFWAddFirewallRule2_31(dce, hPolicyStore, pRule):
    request = FWAddFirewallRule2_31()
    request['hPolicyStore'] = hPolicyStore
    request['pRule'] = pRule
    return dce.request(request)

def hFWSetFirewallRule2_31(dce, hPolicyStore, pRule):
    request = FWSetFirewallRule2_31()
    request['hPolicyStore'] = hPolicyStore
    request['pRule'] = pRule
    return dce.request(request)

def hFWEnumFirewallRules2_31(dce, hPolicyStore, dwFilteredByStatus, dwProfileFilter, wFlags):
    request = FWEnumFirewallRules2_31()
    request['hPolicyStore'] = hPolicyStore
    request['dwFilteredByStatus'] = dwFilteredByStatus
    request['dwProfileFilter'] = dwProfileFilter
    request['wFlags'] = wFlags
    return dce.request(request)

def hFWQueryFirewallRules2_31(dce, hPolicyStore, pQuery, wFlags):
    request = FWQueryFirewallRules2_31()
    request['hPolicyStore'] = hPolicyStore
    request['pQuery'] = pQuery
    request['wFlags'] = wFlags
    return dce.request(request)

def hFWAddFirewallRule2_33(dce, hPolicyStore, pRule):
    request = FWAddFirewallRule2_33()
    request['hPolicyStore'] = hPolicyStore
    request['pRule'] = pRule
    return dce.request(request)

def hFWSetFirewallRule2_33(dce, hPolicyStore, pRule):
    request = FWSetFirewallRule2_33()
    request['hPolicyStore'] = hPolicyStore
    request['pRule'] = pRule
    return dce.request(request)

def hFWEnumFirewallRules2_33(dce, hPolicyStore, dwFilteredByStatus, dwProfileFilter, wFlags):
    request = FWEnumFirewallRules2_33()
    request['hPolicyStore'] = hPolicyStore
    request['dwFilteredByStatus'] = dwFilteredByStatus
    request['dwProfileFilter'] = dwProfileFilter
    request['wFlags'] = wFlags
    return dce.request(request)

def hFWQueryFirewallRules2_33(dce, hPolicyStore, pQuery, wFlags):
    request = FWQueryFirewallRules2_33()
    request['hPolicyStore'] = hPolicyStore
    request['pQuery'] = pQuery
    request['wFlags'] = wFlags
    return dce.request(request)

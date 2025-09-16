// build mingw: g++ -s -Os -std=c++17 platnik-switcher.cpp -o platnik-switcher.exe -ladvapi32 -lshell32

#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <windows.h>

// --- Płatnik Cipher Encryption Logic ---

// Forward declarations for encryption functions
std::string swap(std::string s, int n);
void initialize_keys(std::vector<std::string> &pkey, std::vector<int> &order);

/**
 * @brief Swaps adjacent chunks of size 'n' in a string.
 */
std::string swap(std::string s, int n)
{
    if (n == 0)
        return s;
    std::string result = "";
    for (size_t i = 0; i < s.length(); i += 2 * n)
    {
        std::string chunk1 = s.substr(i, n);
        std::string chunk2 = "";
        if (i + n < s.length())
        {
            chunk2 = s.substr(i + n, n);
        }
        result += chunk2 + chunk1;
    }
    return result;
}

/**
 * @brief Initializes the permutation keys and the order sequence.
 */
void initialize_keys(std::vector<std::string> &pkey, std::vector<int> &order)
{
    std::string k = "lmnopqrstuvwxyz{";

    pkey = {
        swap(k, 8),
        swap(swap(k, 4), 1),
        swap(swap(k, 8), 1),
        swap(k, 1),
        swap(k, 4),
        swap(k, 2),
        swap(swap(k, 2), 1),
        swap(swap(swap(k, 4), 2), 1),
    };

    order = {
        0,
        1,
        2,
        3,
        4,
        0,
        3,
        5,
        2,
        1,
        5,
        4,
        3,
        6,
        6,
        2,
        4,
        2,
        2,
        4,
        3,
        2,
        7,
        7,
    };
}

/**
 * @brief Encrypts a plain text string using the Płatnik cipher algorithm.
 * @param plainText The string to encrypt.
 * @return The encrypted string.
 */
std::string encrypt(const std::string &plainText)
{
    std::vector<std::string> pkey;
    std::vector<int> order;
    initialize_keys(pkey, order);

    std::stringstream encrypted_stream;
    for (size_t i = 0; i < plainText.length(); ++i)
    {
        unsigned char c = plainText[i];
        int a = c & 0x0F;        // Low nibble
        int b = (c >> 4) & 0x0F; // High nibble

        const std::string &current_key = pkey[order[i % 24]];

        if (a < current_key.length() && b < current_key.length())
        {
            encrypted_stream << current_key[a] << current_key[b];
        }
    }
    return encrypted_stream.str();
}

/**
 * @brief Decrypts an encoded string using the Płatnik cipher algorithm.
 * @param encodedText The string to decrypt.
 * @return The decrypted string.
 */
std::string decrypt(const std::string &encodedText)
{
    std::vector<std::string> pkey;
    std::vector<int> order;
    std::string k;
    initialize_keys(pkey, order);
    k = "lmnopqrstuvwxyz{";

    // Filter out invalid characters
    std::string filtered_str;
    for (char c : encodedText)
    {
        if (k.find(c) != std::string::npos)
        {
            filtered_str += c;
        }
    }

    std::string decrypted_text;
    for (size_t i = 0; i < filtered_str.length() / 2; ++i)
    {
        char char1 = filtered_str[i * 2];
        char char2 = filtered_str[i * 2 + 1];

        const std::string &current_key = pkey[order[i % 24]];

        size_t a_pos = current_key.find(char1);
        size_t b_pos = current_key.find(char2);

        if (a_pos != std::string::npos && b_pos != std::string::npos)
        {
            unsigned char original_char_code = (b_pos << 4) | a_pos;
            decrypted_text += static_cast<char>(original_char_code);
        }
    }
    return decrypted_text;
}

// --- Windows Registry Interaction Logic ---

/**
 * @brief Sets a string value in a specific registry key.
 */
void SetRegValue(HKEY hKey, const std::wstring &valueName, const std::wstring &data)
{
    LONG result = RegSetValueExW(
        hKey,
        valueName.c_str(),
        0,
        REG_SZ, // Type is a string
        reinterpret_cast<const BYTE *>(data.c_str()),
        (data.length() + 1) * sizeof(wchar_t) // Size includes null terminator
    );

    if (result == ERROR_SUCCESS)
    {
        std::wcout << L"Successfully set value: " << valueName << std::endl;
    }
    else
    {
        std::wcerr << L"Error setting registry value. Code: " << result << std::endl;
    }
}

/**
 * @brief Deletes a value in a specific registry key.
 */
void DeleteRegValue(HKEY hKey, const std::wstring &valueName)
{
    LONG result = RegDeleteValueW(
        hKey,
        valueName.c_str());

    if (result == ERROR_SUCCESS)
    {
        std::wcout << L"Pomyślnie usunięto wartość: " << valueName << std::endl;
    }
    else
    {
        std::wcerr << L"Błąd podczas usuwania wartości. Kod błędu: " << result << std::endl;
    }
}

/**
 * @brief Gets a string value in a specific registry key.
 */
std::wstring GetRegValue(HKEY hKey, const std::wstring &valueName)
{
    DWORD dataType;
    DWORD dataSize = 0;

    // First, call RegQueryValueExW to get the size of the data.
    LONG result = RegQueryValueExW(
        hKey,
        valueName.c_str(),
        0,
        &dataType,
        NULL,
        &dataSize);

    if (result == ERROR_SUCCESS && dataType == REG_SZ)
    {
        // Allocate a buffer for the data and retrieve it.
        std::wstring data(dataSize / sizeof(wchar_t), L'\0');
        result = RegQueryValueExW(
            hKey,
            valueName.c_str(),
            0,
            &dataType,
            reinterpret_cast<BYTE *>(&data[0]),
            &dataSize);

        if (result == ERROR_SUCCESS)
        {
            std::wcout << L"Successfully retrieved value: " << valueName << std::endl;
            // *** THE CRITICAL FIX IS HERE ***
            // The size from the API includes the null terminator. We must remove it
            // from the C++ string object to avoid embedded nulls.
            size_t null_pos = data.find(L'\0');
            if (null_pos != std::wstring::npos)
            {
                data.resize(null_pos);
            }

            return data;
        }
        else
        {
            std::wcerr << L"Error retrieving registry value. Code: " << result << std::endl;
        }
    }
    else
    {
        std::wcerr << L"Error querying registry value. Code: " << result << std::endl;
    }

    return std::wstring();
}

/**
 * @brief Retrieves the hostname of the current machine.
 * @return The hostname as a std::wstring.
 */
std::wstring get_hostname()
{
    wchar_t computerName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = MAX_COMPUTERNAME_LENGTH + 1;

    // Call the Windows API function to get the computer name.
    if (GetComputerNameW(computerName, &size))
    {
        // Successfully retrieved the name.
        // We use wcout because the function returns a wide-character string (Unicode).
        std::wcout << L"Hostname: " << computerName << std::endl;
    }
    else
    {
        // Failed to retrieve the name.
        DWORD error = GetLastError();
        std::wcerr << L"Failed to get computer name. Error code: " << error << std::endl;
    }
    return std::wstring(computerName);
}

// --- String Conversion Helpers for Windows API ---

/**
 * @brief Converts a Windows command-line argument (from argv[]) to a UTF-8 string.
 *
 * This is necessary because argv[] on Windows uses the system's active ANSI codepage, not UTF-8.
 *
 * @param ansi_str The input string from argv[].
 * @return A std::string containing the correctly converted UTF-8 text.
 */
std::string AnsiArgToUtf8(const char *ansi_str)
{
    if (!ansi_str)
        return "";

    // Step 1: Convert from ANSI (CP_ACP) to UTF-16 (wstring)
    int size_needed_w = MultiByteToWideChar(CP_ACP, 0, ansi_str, -1, NULL, 0);
    if (size_needed_w == 0)
        return "";

    std::wstring wstr(size_needed_w, 0);
    MultiByteToWideChar(CP_ACP, 0, ansi_str, -1, &wstr[0], size_needed_w);

    // Step 2: Convert from UTF-16 (wstring) to UTF-8 (string)
    int size_needed_u8 = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, NULL, 0, NULL, NULL);
    if (size_needed_u8 == 0)
        return "";

    std::string utf8_str(size_needed_u8, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &utf8_str[0], size_needed_u8, NULL, NULL);

    // The result might have extra null terminators, so resize to the actual content length.
    utf8_str.resize(strlen(utf8_str.c_str()));

    return utf8_str;
}
/**
 * @brief Converts a UTF-8 encoded std::string to a UTF-16 encoded std::wstring.
 */
std::wstring Utf8ToWstring(const std::string &utf8_str)
{
    if (utf8_str.empty())
    {
        return std::wstring();
    }
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, utf8_str.c_str(), (int)utf8_str.length(), NULL, 0);
    if (size_needed == 0)
    {
        return std::wstring();
    }
    std::wstring wstrTo(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, utf8_str.c_str(), (int)utf8_str.length(), &wstrTo[0], size_needed);
    return wstrTo;
}

/**
 * @brief Converts a UTF-16 encoded std::wstring to a UTF-8 encoded std::string.
 */
std::string WstringToUtf8(const std::wstring &wstr)
{
    if (wstr.empty())
    {
        return std::string();
    }
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
}

/**
 * @brief Main function to handle registry operations with admin privileges.
 */

int main(int argc, char *argv[])
{
    HKEY hKey;
    const wchar_t *subKey = L"Software\\WOW6432Node\\Asseco Poland SA\\Płatnik\\10.02.002\\Baza";
    LONG result;

    // --- Bonus: Displaying in the console ---
    // Standard std::wcout often fails. To correctly display Polish characters
    // in the MinGW console, you first need to set the console's output codepage.
    SetConsoleOutputCP(CP_UTF8);

    // Redirect std::wcout to the console    // Get password from command-line argument or use default.
    std::string user_name = "Administrator";
    std::string plain_password;
    std::string data_source;
    std::string initial_catalogue = "mdb";
    std::string mode = "ReadWrite";

    std::wstring message = L"Baza Płatnika przełączona.\n\n";
    
    if (argc > 1) {
        data_source = AnsiArgToUtf8(argv[1]);
    }

    bool is_mdb = data_source.find(".mdb") != std::string::npos;

    if (argc == 3 && is_mdb)
    {
        plain_password = AnsiArgToUtf8(argv[2]); // e.g. mojehaslo
        std::cout << "\nUsing database and password from command-line arguments." << std::endl;
        message = L"Przełączenie bazy na:\n\n";
        message += L"Żródło danych (plik bazy):\n" + Utf8ToWstring(data_source) + L"\n";
        message += L"Hasło: " + Utf8ToWstring(plain_password) + L"\n";
    }
    else if (argc >= 3)
    {
        initial_catalogue = AnsiArgToUtf8(argv[2]); // e.g. BazaPlatnika
        if (argc >= 5) {
            user_name = AnsiArgToUtf8(argv[3]);         // e.g. Administrator
            plain_password = AnsiArgToUtf8(argv[4]);    // e.g. mojehaslo
        }
        std::cout << "\nUsing all parameters from command-line arguments." << std::endl;
        message = L"Przełączenie bazy na:\n\n";
        message += L"Żródło danych (host,port):\n\n" + Utf8ToWstring(data_source) + L"\n\n";
        message += L"Katalog: " + Utf8ToWstring(initial_catalogue) + L"\n\n";
        if (argc >= 5) {
            message += L"Użytkownik: " + Utf8ToWstring(user_name) + L"\n\n";
            message += L"Hasło: " + Utf8ToWstring(plain_password) + L"\n";
        } else {
            message += L"Użytkownik: (Integrated Security - SSPI)\n\n";
            message += L"Hasło: (Integrated Security - SSPI)\n";
        }
    }
    else
    {
        std::cout << "\nNo command-line arguments provided. Using default values." << std::endl;

        LONG openResult = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            subKey,
            0,
            KEY_READ,
            &hKey);
        if (openResult != ERROR_SUCCESS)
        {
            std::wcerr << L"Error: Could not open registry key. Code: " << openResult << std::endl;
            return 1;
        }
        plain_password = WstringToUtf8(GetRegValue(hKey, L"Jet OLEDB:Database Password"));

        if (plain_password == "")
        {
            plain_password = WstringToUtf8(GetRegValue(hKey, L"Password"));
        }

        data_source = WstringToUtf8(GetRegValue(hKey, L"Data Source"));
        user_name = WstringToUtf8(GetRegValue(hKey, L"User ID"));
        initial_catalogue = WstringToUtf8(GetRegValue(hKey, L"Initial Catalog"));
        RegCloseKey(hKey);

        message = L"Wywołano bez parametrów.\n\n";
        message += L"Użycie:\n";
        message += L"platnik-start.exe [plik.mdb|host,port] <katalog> [<użytkownik> <hasło>]\n\n";
        message += L"Przykład:\n";
        message += L"platnik-start.exe C:\\Płatnik\\Baza.mdb mojehaslo\n\n";
        message += L"lub\n\n";
        message += L"platnik-start.exe localhost,1433 BazaPlatnika Administrator mojehaslo\n\n";
        message += L"Aktualne ustawienia:\n";
        message += L"Żródło danych (plik bazy lub host,port):\n" + Utf8ToWstring(data_source) + L"\n";
        message += L"Katalog: " + Utf8ToWstring(initial_catalogue) + L"\n";
        message += L"Użytkownik: " + Utf8ToWstring(user_name) + L"\n";
        message += L"Hasło: " + Utf8ToWstring(decrypt(plain_password)) + L"\n";
        std::cout << WstringToUtf8(message).c_str() << std::endl;
    }

    if (argc == 3 || argc == 5)
    {
        // Encrypt the password and set the registry values.
        std::string encrypted_password_str = encrypt(plain_password);
        std::wstring encrypted_password_wstr = Utf8ToWstring(encrypted_password_str);

        std::cout << "Plain text: " << plain_password << std::endl;
        std::cout << "Encrypted:  " << encrypted_password_str << std::endl
                  << std::endl;

        // Open the registry key with write access.
        result = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            subKey,
            0,
            KEY_READ | KEY_WRITE | KEY_SET_VALUE,
            &hKey);

        if (result != ERROR_SUCCESS)
        {
            std::wcerr << L"Error opening registry key. Code: " << result << std::endl;
            message = L"Nie udało się otworzyć klucza rejestru.\n\nZmień uprawnienia na \"Pełna kontrola\" dla klucza:\nHKEY_LOCAL_MACHINE\\";
            message += std::wstring(subKey);
            message += L"\n\nlub uruchom ponownie program jako administrator.";
            argc = 0;
        }
        std::wcout << L"Successfully created/opened key: HKEY_LOCAL_MACHINE\\" << subKey << std::endl;

        
        if (argc == 3 && is_mdb)
        {
            DeleteRegValue(hKey, L"Provider");
            DeleteRegValue(hKey, L"Data Source");
            DeleteRegValue(hKey, L"Initial Catalog");
            DeleteRegValue(hKey, L"Persist Security Info");
            DeleteRegValue(hKey, L"User ID");
            DeleteRegValue(hKey, L"Password");
            DeleteRegValue(hKey, L"Use Procedure for Prepare");
            DeleteRegValue(hKey, L"Auto Translate");
            DeleteRegValue(hKey, L"Pocket Size");
            DeleteRegValue(hKey, L"Workstation ID");
            DeleteRegValue(hKey, L"Integrated Security");

            SetRegValue(hKey, L"Provider", L"Microsoft.Jet.OLEDB.4.0");
            SetRegValue(hKey, L"Data Source", Utf8ToWstring(data_source));
            SetRegValue(hKey, L"Jet OLEDB:Database Password", encrypted_password_wstr);
            SetRegValue(hKey, L"Persist Security Info", L"False");
            SetRegValue(hKey, L"Mode", L"ReadWrite");
        }
        else if (argc >= 3)
        {
            DeleteRegValue(hKey, L"Jet OLEDB:Database Password");
            DeleteRegValue(hKey, L"Mode");
            DeleteRegValue(hKey, L"Password");
            DeleteRegValue(hKey, L"Integrated Security");

            SetRegValue(hKey, L"Provider", L"MSOLEDBSQL");
            SetRegValue(hKey, L"Data Source", Utf8ToWstring(data_source));
            SetRegValue(hKey, L"Initial Catalog", initial_catalogue.empty() ? L"firma" : Utf8ToWstring(initial_catalogue));

            if (argc == 3)
            {
                SetRegValue(hKey, L"Integrated Security", L"SSPI");
                SetRegValue(hKey, L"Persist Security Info", L"False");
            } else {
                SetRegValue(hKey, L"User ID", user_name.empty() ? L"Administrator" : Utf8ToWstring(user_name));
                SetRegValue(hKey, L"Password", encrypted_password_wstr);
                SetRegValue(hKey, L"Persist Security Info", L"True");
            }
            
            SetRegValue(hKey, L"Use Procedure for Prepare", L"1");
            SetRegValue(hKey, L"Auto Translate", L"True");
            SetRegValue(hKey, L"Pocket Size", L"4096");
            SetRegValue(hKey, L"Workstation ID", get_hostname());
        }
        else
        {
            std::wcerr << L"Invalid number of arguments. Expected 3 or 5." << std::endl;
        }
        // Close the key handle when finished.
        RegCloseKey(hKey);
    }

    std::wcout << L"\nRegistry operations complete. Check regedit.exe under HKEY_LOCAL_MACHINE\\" << subKey << std::endl;

    // Display the result in a simple dialog box using MessageBoxW.
    // This is the most minimal UI element available in the Win32 API.
    MessageBoxW(
        NULL,                      // No owner window
        message.c_str(),           // The message to display
        L"Przełączacz Płatnika",   // The title of the message box
        MB_OK | MB_ICONINFORMATION // Specifies an OK button and an Information icon
    );

    return 0;
}

#include <windows.h>
#include <wincrypt.h>
#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
#include <vector>
#include <thread>
#include <atomic>
#include <chrono>
#include <mutex>
#include <cstdlib>

// Глобальные переменные для отслеживания прогресса и найденного пароля
std::atomic<long long> current_combination(0); // Текущая комбинация
std::atomic<bool> password_found(false);       // Флаг, указывающий, найден ли пароль
std::string found_password;                    // Найденный пароль
std::string current_password;                  // Текущий пароль, который подбирается
std::mutex cout_mutex;                         // Мьютекс для синхронизации вывода
std::mutex password_mutex;                     // Мьютекс для синхронизации доступа к found_password и current_password

// Функция для вычисления MD5 хэша
std::string md5(const std::string& str) {
    HCRYPTPROV hProv = 0; // Хэндл для криптопровайдера
    HCRYPTHASH hHash = 0; // Хэндл для хэша
    BYTE rgbHash[16];     // Массив для хранения хэша
    DWORD cbHash = 16;    // Размер хэша (16 байт для MD5)
    CHAR rgbDigits[] = "0123456789abcdef"; // Символы для преобразования в hex

    // Инициализация криптопровайдера
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        std::cerr << "Ошибка при инициализации криптопровайдера." << std::endl;
        return "";
    }

    // Создание хэш-объекта
    if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) {
        std::cerr << "Ошибка при создании хэш-объекта." << std::endl;
        CryptReleaseContext(hProv, 0);
        return "";
    }

    // Добавление данных в хэш
    if (!CryptHashData(hHash, (BYTE*)str.c_str(), str.size(), 0)) {
        std::cerr << "Ошибка при добавлении данных в хэш." << std::endl;
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }

    // Получение хэша
    if (!CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0)) {
        std::cerr << "Ошибка при получении хэша." << std::endl;
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }

    // Преобразование хэша в строку в формате hex
    std::stringstream ss;
    for (DWORD i = 0; i < cbHash; i++) {
        ss << rgbDigits[rgbHash[i] >> 4] << rgbDigits[rgbHash[i] & 0xf];
    }

    // Освобождение ресурсов
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    return ss.str();
}

// Функция для вычисления общего числа комбинаций
long long calculate_total_combinations(size_t charset_size, int password_length) {
    long long result = 1;
    for (int i = 0; i < password_length; ++i) {
        result *= charset_size;
    }
    return result;
}

// Функция для генерации паролей и проверки их хэша
void generate_passwords(int min_length, int max_length, const std::string& charset, const std::string& username, const std::string& realm, const std::string& nonce, const std::string& target_response, const std::string& A2, long long start_index) {
    for (int length = min_length; length <= max_length; ++length) {
        long long total_combinations = calculate_total_combinations(charset.size(), length);

        // Устанавливаем текущую комбинацию на стартовый индекс
        current_combination = start_index;

        while (true) {
            // Получаем следующую комбинацию
            long long i = current_combination.fetch_add(1);
            if (i >= total_combinations || password_found) {
                break;
            }

            std::string password(length, ' ');
            long long temp = i;
            for (int j = 0; j < length; ++j) {
                password[j] = charset[temp % charset.size()];
                temp /= charset.size();
            }

            // Обновление текущего пароля
            {
                std::lock_guard<std::mutex> lock(password_mutex);
                current_password = password;
            }

            // Вычисление хэша A1
            std::string A1 = username + ":" + realm + ":" + password;
            std::string A1_hash = md5(A1);

            // Вычисление хэша ответа
            std::string response = md5(A1_hash + ":" + nonce + ":" + A2);

            // Проверка совпадения с целевым хэшем
            if (response == target_response) {
                std::lock_guard<std::mutex> lock(password_mutex);
                password_found = true;
                found_password = password;
                return;
            }
        }
    }
}

// Функция для вывода прогресса и текущего пароля каждые 5 секунд
void print_progress(long long total_combinations) {
    while (!password_found) {
        std::this_thread::sleep_for(std::chrono::seconds(2));
        long long current = current_combination.load();
        int progress = static_cast<int>((current + 1) * 100.0 / total_combinations);

        std::string current_pass;
        {
            std::lock_guard<std::mutex> lock(password_mutex);
            current_pass = current_password;
        }

        std::lock_guard<std::mutex> lock(cout_mutex);
        std::cout << "PROGRESS: " << progress << "% | CURRENT PASS: " << current_pass << "\r" << std::flush;
    }
}

// Функция для разделения строки по запятой
void split(const std::string& str, std::vector<std::string>& out) {
    std::stringstream ss(str);
    std::string item;
    while (std::getline(ss, item, ',')) {
        out.push_back(item);
    }
}

// Основная функция
int main() {
    // Запрос данных у пользователя
    int start_percentage;
    std::string input, username, realm, nonce, A2, target_response;
    int min_length, max_length;

    std::cout << "Enter start percentage (0-100): ";
    std::cin >> start_percentage;

    if (start_percentage < 0 || start_percentage > 100) {
        std::cerr << "Percentage must be between 0 and 100." << std::endl;
        return 1;
    }

    std::cout << "Enter minimum password length: ";
    std::cin >> min_length;

    std::cout << "Enter maximum password length: ";
    std::cin >> max_length;

    if (min_length <= 0 || max_length <= 0 || min_length > max_length) {
        std::cerr << "Invalid length values. Ensure min length is positive and less than or equal to max length." << std::endl;
        return 1;
    }

    std::cout << "Enter username, realm, nonce, A2, target response (comma-separated): ";
    std::cin.ignore(); // Игнорируем оставшийся символ новой строки
    std::getline(std::cin, input);

    // Разделяем ввод на части
    std::vector<std::string> inputs;
    split(input, inputs);

    if (inputs.size() != 5) {
        std::cerr << "You must enter exactly 5 values." << std::endl;
        return 1;
    }

    username = inputs[0];
    realm = inputs[1];
    nonce = inputs[2];
    A2 = inputs[3];
    target_response = inputs[4];

    // Символы для паролей
    std::string charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890!@#$%&?"; // Символы для паролей

    // Количество комбинаций
    long long total_combinations = 0;
    for (int length = min_length; length <= max_length; ++length) {
        total_combinations += calculate_total_combinations(charset.size(), length);
    }

    // Вычисление начального значения current_combination
    long long start_index = static_cast<long long>(total_combinations * start_percentage / 100);

    // Количество потоков
    unsigned int num_threads = std::thread::hardware_concurrency();
    std::vector<std::thread> threads;

    // Запуск потоков
    for (unsigned int i = 0; i < num_threads; ++i) {
        threads.emplace_back(generate_passwords, min_length, max_length, charset, username, realm, nonce, target_response, A2, start_index);
    }

    // Запуск потока для вывода прогресса
    std::thread progress_thread(print_progress, total_combinations);

    // Ожидание завершения всех потоков
    for (auto& thread : threads) {
        thread.join();
    }

    // Ожидание завершения потока прогресса
    progress_thread.join();

    // Вывод результата
    if (password_found) {
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::cout << "\nPASS: " << found_password << std::endl;
    }
    else {
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::cout << "\nNOPASS." << std::endl;
    }

    // Ожидание нажатия клавиши Enter перед выходом
    std::cout << "Press Enter to exit...";
    std::cin.ignore(); // Игнорируем предыдущий ввод
    std::cin.get();    // Ожидаем нажатия клавиши Enter

    return 0;
}
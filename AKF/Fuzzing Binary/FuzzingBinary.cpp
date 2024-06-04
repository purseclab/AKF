#include <keymaster/keymaster4.h>
#include <keymaster/authorization_set.h>
#include <fstream>
#include <vector>
#include <iostream>
#include <sstream>
#include <unordered_map>
#include <functional>

using namespace keymaster;

bool read_input_data(const char* file_path, std::vector<std::string>& functions) {
    std::ifstream input_file(file_path);
    if (!input_file) {
        std::cerr << "Failed to open input file: " << file_path << std::endl;
        return false;
    }
    std::string line;
    while (std::getline(input_file, line)) {
        functions.push_back(line);
    }
    if (functions.empty()) {
        std::cerr << "Input file is empty: " << file_path << std::endl;
        return false;
    }
    return true;
}

void generate_key(AndroidKeymaster4Device& keymaster_device) {
    keymaster::AuthorizationSet key_params;
    key_params.push_back(TAG_ALGORITHM, KM_ALGORITHM_RSA);
    key_params.push_back(TAG_KEY_SIZE, 2048);
    key_params.push_back(TAG_DIGEST, KM_DIGEST_SHA_2_256);
    key_params.push_back(TAG_PADDING, KM_PAD_RSA_PKCS1_1_5_SIGN);

    keymaster_key_blob_t key_blob;
    keymaster_key_characteristics_t key_characteristics;
    keymaster_error_t error = keymaster_device.generate_key(key_params, &key_blob, &key_characteristics);

    if (error != KM_ERROR_OK) {
        std::cerr << "Key generation failed: " << error << std::endl;
    }

    keymaster_device.free_key_blob(&key_blob);
    keymaster_device.free_characteristics(&key_characteristics);
}

void import_key(AndroidKeymaster4Device& keymaster_device, const uint8_t* data, size_t size) {
    keymaster::AuthorizationSet key_params;
    key_params.push_back(TAG_ALGORITHM, KM_ALGORITHM_RSA);
    key_params.push_back(TAG_KEY_SIZE, 2048);

    keymaster_key_format_t key_format = KM_KEY_FORMAT_PKCS8;
    keymaster_blob_t key_data = { data, size };

    keymaster_key_blob_t key_blob;
    keymaster_key_characteristics_t key_characteristics;
    keymaster_error_t error = keymaster_device.import_key(key_params, key_format, key_data, &key_blob, &key_characteristics);

    if (error != KM_ERROR_OK) {
        std::cerr << "Key import failed: " << error << std::endl;
    }

    keymaster_device.free_key_blob(&key_blob);
    keymaster_device.free_characteristics(&key_characteristics);
}

void import_wrapped_key(AndroidKeymaster4Device& keymaster_device, const uint8_t* data, size_t size) {

    keymaster_key_blob_t wrapped_key = { data, size };
    keymaster_key_blob_t wrapping_key = { data, size };
    keymaster_blob_t masking_key = { data, size };
    keymaster::AuthorizationSet auth_list;

    keymaster_key_blob_t imported_key_blob;
    keymaster_key_characteristics_t imported_key_characteristics;
    keymaster_error_t error = keymaster_device.import_wrapped_key(
        wrapped_key, wrapping_key, masking_key, 0, 0, &imported_key_blob, &imported_key_characteristics);

    if (error != KM_ERROR_OK) {
        std::cerr << "Wrapped key import failed: " << error << std::endl;
    }

    keymaster_device.free_key_blob(&imported_key_blob);
    keymaster_device.free_characteristics(&imported_key_characteristics);
}

void delete_key(AndroidKeymaster4Device& keymaster_device, keymaster_key_blob_t& key_blob) {
    keymaster_error_t error = keymaster_device.delete_key(key_blob);
    if (error != KM_ERROR_OK) {
        std::cerr << "Delete key failed: " << error << std::endl;
    }
}

void delete_all_keys(AndroidKeymaster4Device& keymaster_device) {
    keymaster_error_t error = keymaster_device.delete_all_keys();
    if (error != KM_ERROR_OK) {
        std::cerr << "Delete all keys failed: " << error << std::endl;
    }
}

void abort_operation(AndroidKeymaster4Device& keymaster_device, keymaster_operation_handle_t operation_handle) {
    keymaster_error_t error = keymaster_device.abort(operation_handle);
    if (error != KM_ERROR_OK) {
        std::cerr << "Abort operation failed: " << error << std::endl;
    }
}

void export_key(AndroidKeymaster4Device& keymaster_device, keymaster_key_blob_t& key_blob) {
    keymaster_key_format_t export_format = KM_KEY_FORMAT_X509;
    keymaster_blob_t export_data;

    keymaster_error_t error = keymaster_device.export_key(export_format, key_blob, nullptr, &export_data);
    if (error != KM_ERROR_OK) {
        std::cerr << "Export key failed: " << error << std::endl;
    }

    keymaster_device.free_blob(&export_data);
}

void call_keymaster_functions(const std::vector<std::string>& functions, const uint8_t* data, size_t size) {
    AndroidKeymaster4Device TEE;
    AndroidKeymaster4Device StrongBox;

    keymaster_key_blob_t key_blob;
    keymaster_key_characteristics_t key_characteristics;
    keymaster_operation_handle_t operation_handle;

    std::unordered_map<std::string, std::function<void()>> function_map = {
        {"generate_key", [&]() { generate_key(keymaster_device); }},
        {"import_key", [&]() { import_key(keymaster_device, data, size); }},
        {"import_wrapped_key", [&]() { import_wrapped_key(keymaster_device, data, size); }},
        {"begin_operation", [&]() { begin_operation(keymaster_device, operation_handle, key_blob); }},
        {"update_operation", [&]() { update_operation(keymaster_device, operation_handle, data, size); }},
        {"finish_operation", [&]() { finish_operation(keymaster_device, operation_handle, data, size); }},
        {"delete_key", [&]() { delete_key(keymaster_device, key_blob); }},
        {"delete_all_keys", [&]() { delete_all_keys(keymaster_device); }},
        {"abort_operation", [&]() { abort_operation(keymaster_device, operation_handle); }},
        {"export_key", [&]() { export_key(keymaster_device, key_blob); }}
    };

    for (const auto& func_name : functions) {
        if (function_map.find(func_name) != function_map.end()) {
            function_map[func_name](TEE);
            function_map[func_name](StrongBox);
        } else {
            std::cerr << "Unknown function: " << func_name << std::endl;
        }
    }
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <functions_file_path> <input_file_path>" << std::endl;
        return 1;
    }

    const char* functions_file_path = argv[1];
    const char* input_file_path = argv[2];

    std::vector<std::string> functions;
    if (!read_input_data(functions_file_path, functions)) {
        return 1;
    }

    std::ifstream input_file(input_file_path, std::ios::binary);
    if (!input_file) {
        std::cerr << "Failed to open input file: " << input_file_path << std::endl;
        return 1;
    }
    std::vector<uint8_t> file_data((std::istreambuf_iterator<char>(input_file)), std::istreambuf_iterator<char>());

    if (file_data.empty()) {
        std::cerr << "Input file is empty: " << input_file_path << std::endl;
        return 1;
    }

    call_keymaster_functions(functions, file_data.data(), file_data.size());

    std::ofstream output_file("combined_output", std::ios::binary);
    if (!output_file) {
        std::cerr << "Failed to open output file: " << std::endl;
        return 1;
    }

    return 0;
}

/*
 * Copyright 2019 Google LLC.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "private_join_and_compute/data_util.h"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <limits>
#include <random>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "absl/container/btree_set.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_replace.h"
#include "absl/strings/string_view.h"
#include "private_join_and_compute/crypto/context.h"
#include "private_join_and_compute/util/status.inc"

namespace private_join_and_compute {
namespace {

static const char kAlphaNumericCharacters[] =
    "1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM";
static const size_t kAlphaNumericSize = 62;

// Creates a string of the specified length consistin of random letters and
// numbers.
std::string GetRandomAlphaNumericString(size_t length) {
  std::string output;
  for (size_t i = 0; i < length; i++) {
    std::string next_char(1,
                          kAlphaNumericCharacters[rand() % kAlphaNumericSize]);
    absl::StrAppend(&output, next_char);
  }
  return output;
}

// Utility functions to convert a line to CSV format, and parse a CSV line into
// columns safely.

char* strndup_with_new(const char* the_string, size_t max_length) {
  if (the_string == nullptr) return nullptr;

  char* result = new char[max_length + 1];
  result[max_length] = '\0';  // terminate the string because strncpy might not
  return strncpy(result, the_string, max_length);
}

void SplitCSVLineWithDelimiter(char* line, char delimiter,
                               std::vector<char*>* cols) {
  char* end_of_line = line + strlen(line);
  char* end;
  char* start;

  for (; line < end_of_line; line++) {
    // Skip leading whitespace, unless said whitespace is the delimiter.
    while (std::isspace(*line) && *line != delimiter) ++line;

    if (*line == '"' && delimiter == ',') {  // Quoted value...
      start = ++line;
      end = start;
      for (; *line; line++) {
        if (*line == '"') {
          line++;
          if (*line != '"')  // [""] is an escaped ["]
            break;           // but just ["] is end of value
        }
        *end++ = *line;
      }
      // All characters after the closing quote and before the comma
      // are ignored.
      line = strchr(line, delimiter);
      if (!line) line = end_of_line;
    } else {
      start = line;
      line = strchr(line, delimiter);
      if (!line) line = end_of_line;
      // Skip all trailing whitespace, unless said whitespace is the delimiter.
      for (end = line; end > start; --end) {
        if (!std::isspace(end[-1]) || end[-1] == delimiter) break;
      }
    }
    const bool need_another_column =
        (*line == delimiter) && (line == end_of_line - 1);
    *end = '\0';
    cols->push_back(start);
    // If line was something like [paul,] (comma is the last character
    // and is not proceeded by whitespace or quote) then we are about
    // to eliminate the last column (which is empty). This would be
    // incorrect.
    if (need_another_column) cols->push_back(end);

    assert(*line == '\0' || *line == delimiter);
  }
}

void SplitCSVLineWithDelimiterForStrings(const std::string& line,
                                         char delimiter,
                                         std::vector<std::string>* cols) {
  // Unfortunately, the interface requires char* instead of const char*
  // which requires copying the string.
  char* cline = strndup_with_new(line.c_str(), line.size());
  std::vector<char*> v;
  SplitCSVLineWithDelimiter(cline, delimiter, &v);
  for (char* str : v) {
    cols->push_back(str);
  }
  delete[] cline;
}

// Escapes a string for CSV file writing. By default, this will surround each
// string with double quotes, and escape each occurrence of a double quote by
// replacing it with 2 double quotes.
std::string EscapeForCsv(absl::string_view input) {
  return absl::StrCat("\"", absl::StrReplaceAll(input, {{"\"", "\"\""}}), "\"");
}

}  // namespace

std::vector<std::string> SplitCsvLine(const std::string& line) {
  std::vector<std::string> cols;
  SplitCSVLineWithDelimiterForStrings(line, ',', &cols);
  return cols;
}

auto GenerateRandomDatabases(int64_t server_data_size, int64_t client_data_size,
                             int64_t intersection_size,
                             int64_t max_associated_value)
    -> StatusOr<std::tuple<
        std::vector<std::string>,
        std::pair<std::vector<std::string>, std::vector<int64_t>>, int64_t>> {
  // Check parameters
  if (intersection_size < 0 || server_data_size < 0 || client_data_size < 0 ||
      max_associated_value < 0) {
    return InvalidArgumentError(
        "GenerateRandomDatabases: Sizes cannot be negative.");
  }
  if (intersection_size > server_data_size ||
      intersection_size > client_data_size) {
    return InvalidArgumentError(
        "GenerateRandomDatabases: intersection_size is larger than "
        "client/server data size.");
  }

  if (max_associated_value > 0 &&
      intersection_size >
          std::numeric_limits<int64_t>::max() / max_associated_value) {
    return InvalidArgumentError(
        "GenerateRandomDatabases: intersection_size * max_associated_value  is "
        "larger than int64_t::max.");
  }

  std::random_device rd;
  std::mt19937 gen(rd());

  // Generate the random identifiers that are going to be in the intersection.
  std::vector<std::string> common_identifiers;
  common_identifiers.reserve(intersection_size);
  for (int64_t i = 0; i < intersection_size; i++) {
    common_identifiers.push_back(
        GetRandomAlphaNumericString(kRandomIdentifierLengthBytes));
  }

  // Generate remaining random identifiers for the server, and shuffle.
  std::vector<std::string> server_identifiers = common_identifiers;
  server_identifiers.reserve(server_data_size);
  for (int64_t i = intersection_size; i < server_data_size; i++) {
    server_identifiers.push_back(
        GetRandomAlphaNumericString(kRandomIdentifierLengthBytes));
  }
  std::shuffle(server_identifiers.begin(), server_identifiers.end(), gen);

  // Generate remaining random identifiers for the client.
  std::vector<std::string> client_identifiers = common_identifiers;
  client_identifiers.reserve(client_data_size);
  for (int64_t i = intersection_size; i < client_data_size; i++) {
    client_identifiers.push_back(
        GetRandomAlphaNumericString(kRandomIdentifierLengthBytes));
  }
  std::shuffle(client_identifiers.begin(), client_identifiers.end(), gen);

  absl::btree_set<std::string> server_identifiers_set(
      server_identifiers.begin(), server_identifiers.end());

  // Generate associated values for the client, adding them to the intersection
  // sum if the identifier is in common.
  std::vector<int64_t> client_associated_values;
  Context context;
  BigNum associated_values_bound = context.CreateBigNum(max_associated_value);
  client_associated_values.reserve(client_data_size);
  int64_t intersection_sum = 0;
  for (int64_t i = 0; i < client_data_size; i++) {
    // Converting the associated value from BigNum to int64_t should never fail
    // because associated_values_bound is less than int64_t::max.
    int64_t associated_value =
        context.GenerateRandLessThan(associated_values_bound)
            .ToIntValue()
            .value();
    client_associated_values.push_back(associated_value);

    if (server_identifiers_set.count(client_identifiers[i]) > 0) {
      intersection_sum += associated_value;
    }
  }

  // Return the output.
  return std::make_tuple(std::move(server_identifiers),
                         std::make_pair(std::move(client_identifiers),
                                        std::move(client_associated_values)),
                         intersection_sum);
}

Status WriteServerDatasetToFile(const std::vector<std::string>& server_data,
                                absl::string_view server_data_filename) {
  // Open file.
  std::ofstream server_data_file;
  server_data_file.open(std::string(server_data_filename));
  if (!server_data_file.is_open()) {
    return InvalidArgumentError(absl::StrCat(
        "WriteServerDatasetToFile: Couldn't open server data file: ",
        server_data_filename));
  }

  // Write each (escaped) line to file.
  for (const auto& identifier : server_data) {
    server_data_file << EscapeForCsv(identifier) << "\n";
  }

  // Close file.
  server_data_file.close();
  if (server_data_file.fail()) {
    return InternalError(
        absl::StrCat("WriteServerDatasetToFile: Couldn't write to or close "
                     "server data file: ",
                     server_data_filename));
  }

  return OkStatus();
}

Status WriteClientDatasetToFile(
    const std::vector<std::string>& client_identifiers,
    const std::vector<int64_t>& client_associated_values,
    absl::string_view client_data_filename) {
  if (client_associated_values.size() != client_identifiers.size()) {
    return InvalidArgumentError(
        "WriteClientDatasetToFile: there should be the same number of client "
        "identifiers and associated values.");
  }

  // Open file.
  std::ofstream client_data_file;
  client_data_file.open(std::string(client_data_filename));
  if (!client_data_file.is_open()) {
    return InvalidArgumentError(absl::StrCat(
        "WriteClientDatasetToFile: Couldn't open client data file: ",
        client_data_filename));
  }

  // Write each (escaped) line to file.
  for (size_t i = 0; i < client_identifiers.size(); i++) {
    client_data_file << absl::StrCat(EscapeForCsv(client_identifiers[i]), ",",
                                     client_associated_values[i])
                     << "\n";
  }

  // Close file.
  client_data_file.close();
  if (client_data_file.fail()) {
    return InternalError(
        absl::StrCat("WriteClientDatasetToFile: Couldn't write to or close "
                     "client data file: ",
                     client_data_filename));
  }

  return OkStatus();
}

StatusOr<std::vector<std::string>> ReadServerDatasetFromFile(
    absl::string_view server_data_filename) {
  // Open file.
  std::ifstream server_data_file;
  server_data_file.open(std::string(server_data_filename));
  if (!server_data_file.is_open()) {
    return InvalidArgumentError(absl::StrCat(
        "ReadServerDatasetFromFile: Couldn't open server data file: ",
        server_data_filename));
  }

  // Read each line from file (unescaping and splitting columns). Verify that
  // each line contains a single column
  std::vector<std::string> server_data;
  std::string line;
  int64_t line_number = 0;
  while (std::getline(server_data_file, line)) {
    std::vector<std::string> columns = SplitCsvLine(line);
    if (columns.size() != 1) {
      return InvalidArgumentError(absl::StrCat(
          "ReadServerDatasetFromFile: Expected exactly 1 identifier per line, "
          "but line ",
          line_number, "has ", columns.size(),
          " comma-separated items (file: ", server_data_filename, ")"));
    }
    server_data.push_back(columns[0]);
    line_number++;
  }

  // Close file.
  server_data_file.close();
  if (server_data_file.is_open()) {
    return InternalError(absl::StrCat(
        "ReadServerDatasetFromFile: Couldn't close server data file: ",
        server_data_filename));
  }

  return server_data;
}

StatusOr<std::pair<std::vector<std::string>, std::vector<BigNum>>>
ReadClientDatasetFromFile(absl::string_view client_data_filename,
                          Context* context) {
  // Open file.
  std::ifstream client_data_file;
  client_data_file.open(std::string(client_data_filename));
  if (!client_data_file.is_open()) {
    return InvalidArgumentError(absl::StrCat(
        "ReadClientDatasetFromFile: Couldn't open client data file: ",
        client_data_filename));
  }

  // Read each line from file (unescaping and splitting columns). Verify that
  // each line contains two columns, and parse the second column into an
  // associated value.
  std::vector<std::string> client_identifiers;
  std::vector<BigNum> client_associated_values;
  std::string line;
  int64_t line_number = 0;
  while (std::getline(client_data_file, line)) {
    std::vector<std::string> columns = SplitCsvLine(line);
    if (columns.size() != 2) {
      return InvalidArgumentError(absl::StrCat(
          "ReadClientDatasetFromFile: Expected exactly 2 items per line, "
          "but line ",
          line_number, "has ", columns.size(),
          " comma-separated items (file: ", client_data_filename, ")"));
    }
    client_identifiers.push_back(columns[0]);
    int64_t parsed_associated_value;
    if (!absl::SimpleAtoi(columns[1], &parsed_associated_value) ||
        parsed_associated_value < 0) {
      return InvalidArgumentError(
          absl::StrCat("ReadClientDatasetFromFile: could not parse a "
                       "nonnegative associated value at line number",
                       line_number));
    }
    client_associated_values.push_back(
        context->CreateBigNum(parsed_associated_value));
    line_number++;
  }

  // Close file.
  client_data_file.close();
  if (client_data_file.is_open()) {
    return InternalError(absl::StrCat(
        "ReadClientDatasetFromFile: Couldn't close client data file: ",
        client_data_filename));
  }

  return std::make_pair(std::move(client_identifiers),
                        std::move(client_associated_values));
}

}  // namespace private_join_and_compute

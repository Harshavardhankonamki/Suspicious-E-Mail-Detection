#include <iostream>
#include <vector>
#include <algorithm>
#include <cctype>
#include <locale>
#include <string>
#include <regex>
#include <fstream>

bool isSuspiciousKeyword(const std::string& text) {
    // Open the suspicious words file
    std::ifstream suspiciousWordsFile("suspicious_words.txt");
    if (!suspiciousWordsFile.is_open()) {
        std::cerr << "Unable to open the suspicious words file: suspicious_words.txt\n";
        return false;
    }

    std::vector<std::string> keywords;
    std::string word;

    // Read suspicious words from the file and populate the keywords vector
    while (std::getline(suspiciousWordsFile, word)) {
        keywords.push_back(word);
    }

    // Close the file
    suspiciousWordsFile.close();

    // Convert the text to lowercase
    std::string lowercaseText = text;
    std::transform(lowercaseText.begin(), lowercaseText.end(), lowercaseText.begin(), ::tolower);

    // Check for suspicious keywords
    for (const std::string& keyword : keywords) {
        if (lowercaseText.find(keyword) != std::string::npos) {
            return true;
        }
    }
    return false;
}

bool isValidDomain(const std::string& email) {
    // Extract the domain part of the email
    std::smatch match;
    std::regex pattern(R"(@([\w.-]+)$)");
    if (std::regex_search(email, match, pattern)) {
        std::string domain = match[1].str();
        
        // Implement more rigorous domain checks here, e.g., using DNS queries, for a production system.
        if (domain.find('.') != std::string::npos) {
            return true;
        }
    }
    return false;
}

bool isWhitelisted(const std::string& email) {
    std::ifstream inputFile("whitelist.txt");
    std::string whitelistedEmail;

    if (inputFile.is_open()) {
        while (std::getline(inputFile, whitelistedEmail)) {
            if (email == whitelistedEmail) {
                return true;
            }
        }
        inputFile.close();
    } else {
        std::cerr << "Unable to open the whitelist file: whitelist.txt\n";
    }
    return false;
}

bool isBlacklisted(const std::string& email) {
    std::ifstream inputFile("blacklist.txt");
    std::string blacklistedEmail;

    if (inputFile.is_open()) {
        while (std::getline(inputFile, blacklistedEmail)) {
            if (email == blacklistedEmail) {
                inputFile.close();
                return true;
            }
        }
        inputFile.close();
    } else {
        std::cerr << "Unable to open the blacklist file: blacklist.txt\n";
    }
    return false;
}

void addToBlacklist(const std::string& email) {
    std::ofstream blacklistFile("blacklist.txt", std::ios::app);
    if (blacklistFile.is_open()) {
        blacklistFile << email << "\n";
        blacklistFile.close();
    } else {
        std::cerr << "Unable to open the blacklist file for writing: blacklist.txt\n";
    }
}

void addToWhitelist(const std::string& email) {
    std::ofstream whitelistFile("whitelist.txt", std::ios::app);
    if (whitelistFile.is_open()) {
        whitelistFile << email << "\n";
        whitelistFile.close();
    } else {
        std::cerr << "Unable to open the whitelist file for writing: whitelist.txt\n";
    }
}

void logFlaggedEmail(const std::string& email, const std::string& reason) {
    std::ofstream logFile("flagged_emails.txt", std::ios::app);
    if (logFile.is_open()) {
        logFile << "Flagged Email: " << email << "\n";
        logFile << "Reason: " << reason << "\n\n";
        logFile.close();
        addToBlacklist(email); // Add the flagged email to the blacklist
    } else {
        std::cerr << "Unable to open the log file for writing: flagged_emails.txt\n";
    }
}

int main() {
    std::string choice;

    std::cout << "Choose an option:\n";
    std::cout << "1. Email Processing\n";
    std::cout << "2. Process a single email\n";
    std::cout << "Enter your choice: ";
    std::getline(std::cin, choice);

    if (choice == "1") {
        std::string email;
        std::cout << "Enter an email to check: ";
        std::getline(std::cin, email);

        if (isBlacklisted(email)) {
            std::cout << "The email is blacklisted and considered suspicious." << std::endl;
        } else if (isWhitelisted(email)) {
            std::cout << "The email is whitelisted and considered safe." << std::endl;
        } else {
            std::cout << "The email is not blacklisted or whitelisted." << std::endl;
        }
    } else if (choice == "2") {
        std::string email;
        std::string body;

        std::cout << "Enter email: ";
        std::getline(std::cin, email);

        std::cout << "Enter email body: ";
        std::getline(std::cin, body);

        int score = 0;
        std::string reasons;

        if (isWhitelisted(email)) {
            std::cout << "The email is whitelisted and considered safe." << std::endl;

            if (isSuspiciousKeyword(body)) {
                std::cout << "The email body contains suspicious keywords." << std::endl;
                reasons += "Contains suspicious keywords in the email body. ";
            }

            addToWhitelist(email); // Add the safe email to the whitelist
            return 0;
        }

        if (isBlacklisted(email)) {
            std::cout << "The email is blacklisted and considered suspicious." << std::endl;
            return 0;
        }

        if (isSuspiciousKeyword(email)) {
            score += 2;
            reasons += "Contains suspicious keywords in the email address. ";
        }

        if (isSuspiciousKeyword(body)) {
            score += 2;
            reasons += "Contains suspicious keywords in the email body. ";
        }

        if (!isValidDomain(email)) {
            score += 1;
            reasons += "Invalid domain in the email address. ";
        }

        if (score > 0) {
            std::cout << "The email is suspicious with a score of " << score << "\n";
            std::cout << "Reasons: " << reasons << "\n";

            // Log the flagged email
            logFlaggedEmail(email, reasons);

            // Perform additional actions here, such as notifying administrators or blocking the email.
        } else {
            std::cout << "The email is not suspicious." << std::endl;
            addToWhitelist(email); // Add the safe email to the whitelist
        }
    } else {
        std::cerr << "Invalid choice. Please choose 1 or 2.\n";
    }

    return 0;
}

import hashlib
import time
import argparse

def crack_hash(hash_file_path, hash_type, wordlist_path):
    """
    Attempts to crack hashes in a file using a dictionary attack.

    Args:
        hash_file_path: Path to the file containing hashes (one hash per line).
        hash_type: The type of hash (e.g., "md5", "sha256").
        wordlist_path: Path to the wordlist file.

    Returns:
        A dictionary where keys are the cracked hashes and values are the corresponding passwords.
        Also returns the total time taken.
    """

    start_time = time.time()
    cracked_hashes = {}

    try:
        with open(hash_file_path, "r") as hash_file:
            hashes = [line.strip() for line in hash_file]  # Read hashes from the file

        with open(wordlist_path, "r", encoding="latin-1") as wordlist:
            for word in wordlist:
                word = word.strip()
                if hash_type == "md5":
                    hashed_word = hashlib.md5(word.encode()).hexdigest()
                elif hash_type == "sha256":
                    hashed_word = hashlib.sha256(word.encode()).hexdigest()
                else:
                    print(f"Error: Unsupported hash type {hash_type}")
                    return cracked_hashes, 0


                for hash_value in hashes:  # Check against all hashes
                    if hashed_word == hash_value:
                        cracked_hashes[hash_value] = word
                        hashes.remove(hash_value) #Remove found one from list so it doesnt keep checking it


        end_time = time.time()
        return cracked_hashes, end_time - start_time

    except FileNotFoundError as e:
        print(f"Error: File not found: {e}")
        return cracked_hashes, 0



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Brute-force hash cracker")
    parser.add_argument("hash_file", help="Path to the file containing hashes") # changed argument name
    parser.add_argument("-t", "--type", choices=["md5", "sha256"], default="md5", help="Hash type")
    parser.add_argument("-w", "--wordlist", default="rockyou.txt", help="Path to wordlist")

    args = parser.parse_args()

    cracked_hashes, time_taken = crack_hash(args.hash_file, args.type, args.wordlist)  # Use hash_file


    if cracked_hashes:
        print("Cracked Hashes:")
        for hash_value, password in cracked_hashes.items():
            print(f"{hash_value}: {password}")
        print(f"Time taken: {time_taken:.4f} seconds")

        success_rate = (len(cracked_hashes) / (len(cracked_hashes)))*100 if cracked_hashes else 0  # Calculate success rate
        print(f"Success rate: {success_rate:.2f}%") #Changed to show always 100 or 0 for now

    else:
        print("No matching passwords found in the wordlist.")
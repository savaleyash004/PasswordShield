"""Utility module for password strength calculation and related calculations."""
import math
import secrets
import unicodedata
import random
import hashlib
import requests
import subprocess
import os
import json
import time
import re
from typing import Any, Dict, List, Tuple, Optional, Union

from src.interface.config import CustomData
from src.middleware.logger import logger
from src.pipe.pipeline import Pipeline

CHARS_SET = (
    "qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM1234567890!@#$%^&*. ~()_+={}[]|\\:;'\"<>/?`,`- "
)
# This is now a fallback value if hashcat benchmarking fails
CRACK_PASSWORD_PER_SECOND = 1000000000
SECONDS_IN_MINUTE = 60
SECONDS_IN_HOUR = 60 * 60
SECONDS_IN_DAY = 24 * 60 * 60
SECONDS_IN_MONTH = 30 * 24 * 60 * 60
SECONDS_IN_YEAR = 365 * 24 * 60 * 60
SECONDS_IN_CENTURY = 100 * 365 * 24 * 60 * 60

# Extended character set that includes common symbols/special characters
EXTENDED_SPECIAL_CHARS = (
    "!@#$%^&*. ~()_+={}[]|\\:;'\"<>/?`,`- "  # Basic ASCII special characters
    "£¥€¢¤¦§¨©®¯°±²³´µ¶·¸¹º»¼½¾¿×÷"  # Currency, typographic, and mathematical symbols
    "ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞß"  # Latin-1 Supplement uppercase and symbols
    "àáâãäåæçèéêëìíîïðñòóôõö÷øùúûüýþÿ"  # Latin-1 Supplement lowercase
)

# Hashcat mode IDs for common hash types
HASHCAT_MODES = {
    'md5': 0,        # MD5
    'sha1': 100,     # SHA1
    'sha256': 1400,  # SHA2-256
    'sha512': 1700,  # SHA2-512
    'ntlm': 1000,    # NTLM
    'bcrypt': 3200,  # bcrypt
    'wpa2': 2500,    # WPA/WPA2
    'argon2id': 10900, # Argon2id
    'scrypt': 8900    # scrypt
}

# Stores benchmark results with timestamp for caching
_BENCHMARK_CACHE = {
    'timestamp': 0,
    'results': {},
    'default_hashes_per_second': CRACK_PASSWORD_PER_SECOND
}

# Cache timeout in seconds (benchmark every 24 hours)
_BENCHMARK_CACHE_TIMEOUT = 86400

# Mapping of Unicode script ranges to human-readable names
SCRIPT_RANGES = {
    'Latin': [
        (0x0020, 0x007F),  # Basic Latin
        (0x00A0, 0x00FF),  # Latin-1 Supplement
        (0x0100, 0x017F),  # Latin Extended-A
        (0x0180, 0x024F),  # Latin Extended-B
        (0x1E00, 0x1EFF),  # Latin Extended Additional
    ],
    'Cyrillic': [
        (0x0400, 0x04FF),  # Cyrillic
        (0x0500, 0x052F),  # Cyrillic Supplement
    ],
    'Greek': [
        (0x0370, 0x03FF),  # Greek
        (0x1F00, 0x1FFF),  # Greek Extended
    ],
    'Arabic': [
        (0x0600, 0x06FF),  # Arabic
        (0x0750, 0x077F),  # Arabic Supplement
        (0x08A0, 0x08FF),  # Arabic Extended-A
    ],
    'Hebrew': [(0x0590, 0x05FF)],  # Hebrew
    
    # Indian scripts with full ranges
    'Devanagari': [(0x0900, 0x097F)],  # Devanagari (Hindi, Sanskrit, Marathi, etc.)
    'Bengali': [(0x0980, 0x09FF)],  # Bengali
    'Gurmukhi': [(0x0A00, 0x0A7F)],  # Gurmukhi (Punjabi)
    'Gujarati': [(0x0A80, 0x0AFF)],  # Gujarati
    'Oriya': [(0x0B00, 0x0B7F)],  # Oriya (Odia)
    'Tamil': [(0x0B80, 0x0BFF)],  # Tamil
    'Telugu': [(0x0C00, 0x0C7F)],  # Telugu
    'Kannada': [(0x0C80, 0x0CFF)],  # Kannada
    'Malayalam': [(0x0D00, 0x0D7F)],  # Malayalam
    'Sinhala': [(0x0D80, 0x0DFF)],  # Sinhala
    
    'Thai': [(0x0E00, 0x0E7F)],  # Thai
    'Lao': [(0x0E80, 0x0EFF)],  # Lao
    'Tibetan': [(0x0F00, 0x0FFF)],  # Tibetan
    'Myanmar': [(0x1000, 0x109F)],  # Myanmar (Burmese)
    'Georgian': [(0x10A0, 0x10FF)],  # Georgian
    'Hangul': [
        (0xAC00, 0xD7AF),  # Hangul Syllables (Korean)
        (0x1100, 0x11FF),  # Hangul Jamo
    ],
    'Ethiopic': [(0x1200, 0x137F)],  # Ethiopic
    'Armenian': [(0x0530, 0x058F)],  # Armenian
    'Chinese/Japanese': [
        (0x4E00, 0x9FFF),  # CJK Unified Ideographs (Chinese, Japanese, Korean)
        (0x3400, 0x4DBF),  # CJK Unified Ideographs Extension A
        (0x20000, 0x2A6DF),  # CJK Unified Ideographs Extension B
    ],
    'Japanese-Specific': [
        (0x3040, 0x309F),  # Hiragana
        (0x30A0, 0x30FF),  # Katakana
    ],
    'Khmer': [(0x1780, 0x17FF)],  # Khmer (Cambodian)
    'Mongolian': [(0x1800, 0x18AF)],  # Mongolian
}

# Pre-defined sample characters for Indian scripts to ensure they work properly
INDIAN_SCRIPT_SAMPLES = {
    'Devanagari': "अआइईउऊएऐओऔकखगघङचछजझञटठडढणतथदधनपफबभमयरलवशषसह",
    'Bengali': "অআইঈউঊএঐওঔকখগঘঙচছজঝঞটঠডঢণতথদধনপফবভমযরলশষসহ",
    'Gurmukhi': "ਅਆਇਈਉਊਏਐਓਔਕਖਗਘਙਚਛਜਝਞਟਠਡਢਣਤਥਦਧਨਪਫਬਭਮਯਰਲਵਸ਼ਸਹ",
    'Gujarati': "અઆઇઈઉઊએઐઓઔકખગઘઙચછજઝઞટઠડઢણતથદધનપફબભમયરલવશષસહ",
    'Oriya': "ଅଆଇଈଉଊଏଐଓଔକଖଗଘଙଚଛଜଝଞଟଠଡଢଣତଥଦଧନପଫବଭମଯରଲଶଷସହ",
    'Tamil': "அஆஇஈஉஊஎஏஐஒஓஔகஙசஜஞடணதநபமயரலவழளறன",
    'Telugu': "అఆఇఈఉఊఎఏఐఒఓఔకఖగఘఙచఛజఝఞటఠడఢణతథదధనపఫబభమయరలవశషసహ",
    'Kannada': "ಅಆಇಈಉಊಎಏಐಒಓಔಕಖಗಘಙಚಛಜಝಞಟಠಡಢಣತಥದಧನಪಫಬಭಮಯರಲವಶಷಸಹ",
    'Malayalam': "അആഇഈഉഊഏഐഒഓഔകഖഗഘങചഛജഝഞടഠഡഢണതഥദധനപഫബഭമയരലവശഷസഹ",
}


def detect_scripts(text: str) -> Tuple[bool, List[str]]:
    """Detect which writing systems/scripts are used in the text.
    
    Args:
        text (str): The text to analyze
        
    Returns:
        Tuple[bool, List[str]]: A tuple containing:
            - Boolean indicating if non-Latin characters are present
            - List of script names detected in the text
    """
    used_scripts = set()
    has_non_latin = False
    special_chars_count = 0
    
    # Check explicitly for Devanagari
    has_devanagari = False
    for char in text:
        if 0x0900 <= ord(char) <= 0x097F:
            has_devanagari = True
            used_scripts.add("Devanagari")
            has_non_latin = True
    
    # If Devanagari was found, add it
    if has_devanagari:
        logger.info("Detected Devanagari script in password")
    
    for char in text:
        # Get Unicode category for this character
        category = unicodedata.category(char)
        
        # Check for special characters and symbols (count them but don't assign to a script)
        if category.startswith('S') or category.startswith('P') or category.startswith('Z'):
            special_chars_count += 1
            continue
            
        # Skip other non-letter characters
        if not category.startswith('L'):
            continue
            
        # Skip Devanagari as we already handled it
        if 0x0900 <= ord(char) <= 0x097F:
            continue
            
        # Check which script the character belongs to
        char_code = ord(char)
        found_script = False
        
        for script_name, ranges in SCRIPT_RANGES.items():
            for start, end in ranges:
                if start <= char_code <= end:
                    used_scripts.add(script_name)
                    if script_name != 'Latin':
                        has_non_latin = True
                    found_script = True
                    break
            if found_script:
                break
                
        # If we couldn't identify the script, mark it as "Other"
        if not found_script and category.startswith('L'):
            used_scripts.add("Other")
            has_non_latin = True
    
    # If we have significant special characters, note that
    if special_chars_count > 0 and len(used_scripts) == 0:
        used_scripts.add("Symbols Only")
    
    return has_non_latin, sorted(list(used_scripts))


def generate_password(length: int, include_non_latin: bool = False) -> str:
    """Generate a random password of a given length.

    Args:
        length (int): The length of the password.
        include_non_latin (bool, optional): Whether to include non-Latin characters.

    Returns:
        str: The generated password.
    """
    # For Latin-only passwords, include extended special characters
    if not include_non_latin:
        charset = CHARS_SET + EXTENDED_SPECIAL_CHARS
        return "".join(secrets.choice(charset) for _ in range(length))
    
    # If non-Latin is requested, include characters from all supported writing systems
    non_latin_chars = ""
    
    # For Indian scripts, use pre-defined sample characters to ensure proper rendering
    for script_name, sample in INDIAN_SCRIPT_SAMPLES.items():
        non_latin_chars += sample
    
    # Sample characters from other script ranges (avoiding control characters and other special cases)
    for script, ranges in SCRIPT_RANGES.items():
        if script == 'Latin' or script in INDIAN_SCRIPT_SAMPLES:  # Skip Latin and already added Indian scripts
            continue
            
        # Add a selection of characters from each range
        for start, end in ranges:
            # Sample at most 20 characters from each range to keep the charset manageable
            sample_size = min(20, end - start + 1)
            step = max(1, (end - start + 1) // sample_size)
            
            for code_point in range(start, end + 1, step):
                try:
                    # Convert code point to character and add to our charset
                    char = chr(code_point)
                    # Skip control characters, whitespace, and other problematic characters
                    if not unicodedata.category(char).startswith(('C', 'Z')) and char.isprintable():
                        non_latin_chars += char
                except (ValueError, UnicodeEncodeError):
                    # Skip code points that can't be encoded
                    continue
    
    # Create a character set that combines Latin, special characters, and non-Latin
    latin_charset = CHARS_SET + EXTENDED_SPECIAL_CHARS
    extended_charset = latin_charset + non_latin_chars
    
    # Generate password with roughly 60% Latin/special chars and 40% non-Latin distribution
    password = ""
    for _ in range(length):
        # 60% chance to use Latin/special chars, 40% chance to use non-Latin
        if random.random() < 0.6:
            password += secrets.choice(latin_charset)
        else:
            password += secrets.choice(non_latin_chars)
    
    return password


def calc_strength(password: str) -> float | Any:
    """Calculate the strength of a given password.

    Args:
        password (str): The password to calculate the strength for.

    Returns:
        float: The calculated strength of the password between 0 and 1.
    """
    # Get base strength from model
    custom_data = CustomData()
    pipeline = Pipeline()
    password_df = custom_data.data2df(password)
    base_strength = custom_data.array2data(pipeline.predict(password_df))
    
    # Adjust the base strength based on length
    length = len(password)
    if length <= 6:
        length_factor = 0.2  # Weak (formerly Very weak)
    elif length <= 10:
        length_factor = 0.4  # Weak
    elif length <= 13:
        length_factor = 0.6  # Moderate (formerly Average)
    elif length <= 18:
        length_factor = 0.8  # Strong
    else:
        length_factor = 1.0  # Very strong
    
    # Check if password contains only letters (no numbers or special chars)
    has_only_letters = password.isalpha()
    
    # If password has only letters, reduce strength by one level
    if has_only_letters:
        length_factor = max(0.0, length_factor - 0.2)  # Reduce by one level
    
    # Blend the model's strength with our length-based factor
    adjusted_strength = 0.3 * base_strength + 0.7 * length_factor
    
    return adjusted_strength


def calc_class_strength(value: float, password: str = None) -> str:
    """Calculate the class strength based on a strength value and password characteristics.

    Args:
        value (float): The strength value.
        password (str, optional): The password to check for character diversity.

    Returns:
        str: The class strength category.
    """
    # First determine class based on length thresholds
    if password:
        length = len(password)
        
        # Length-based classification
        if length <= 6:
            length_class = "Weak"
        elif length <= 10:
            length_class = "Weak"
        elif length <= 13:
            length_class = "Moderate"
        elif length <= 18:
            length_class = "Strong"
        else:
            length_class = "Very strong"
        
        # Check if password has only letters (no numbers or special characters)
        has_only_letters = password.isalpha()
        
        # If password has only letters, decrease strength by one level
        if has_only_letters:
            if length_class == "Very strong":
                return "Strong"
            elif length_class == "Strong":
                return "Moderate"
            elif length_class == "Moderate":
                return "Weak"
            elif length_class == "Weak":
                return "Weak"
            # If already Weak, it stays Weak
            return "Weak"
        
        # If it has numbers or special characters, return the length-based class
        return length_class
    
    # If no password provided or as a fallback, use the original value-based thresholds
    return (
        "Weak"
        if value <= 0.2
        else "Weak"
        if value <= 0.4
        else "Moderate"
        if value <= 0.6
        else "Strong"
        if value <= 0.8
        else "Very strong"
    )


def calc_entropy(password: str) -> float:
    """Calculate the entropy of a given password.

    Args:
        password (str): The password to calculate entropy for.

    Returns:
        float: The calculated entropy.
    """
    cardinality = calc_cardinality(password)
    length = len(password)
    sample_space = (cardinality) ** (length)
    return math.log(sample_space, 2)


def calc_cardinality(password: str) -> int:
    """Calculate the cardinality of a password.

    Args:
        password (str): The password to calculate cardinality for.

    Returns:
        int: The calculated cardinality.
    """
    lower, upper, digits, symbols = 0, 0, 0, 0
    for char in password:
        if char.islower():
            lower += 1
        elif char.isdigit():
            digits += 1
        elif char.isupper():
            upper += 1
        else:
            symbols += 1
    return lower + digits + upper + symbols


def run_hashcat_benchmark(hash_mode: int = 0) -> Dict[str, int]:
    """Run hashcat benchmark and return results.
    
    Args:
        hash_mode: Specific hash mode to benchmark. Default is MD5 (0) for faster benchmarking.
        
    Returns:
        Dict with hash modes as keys and hashes/second as values
    """
    try:
        # Get the path to our hashcat wrapper script
        current_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
        wrapper_path = os.path.join(current_dir, "hashcat_wrapper.py")
        
        # Check if hashcat is installed via the wrapper
        try:
            version_check = subprocess.run(
                ["python", wrapper_path, "--version"], 
                capture_output=True, 
                text=True, 
                check=True
            )
            logger.info(f"Hashcat version: {version_check.stdout.strip()}")
        except (subprocess.SubprocessError, FileNotFoundError) as e:
            logger.warning(f"Hashcat not installed or wrapper not found: {str(e)}")
            return {}
            
        # Prepare benchmark command - always specify a hash mode for faster benchmarking
        cmd = ["python", wrapper_path, "-b"]
        # Always include a specific hash mode to make benchmarking faster
        cmd.extend(["-m", str(hash_mode)])
            
        # Add --machine-readable for easier parsing
        cmd.append("--machine-readable")
        
        # Run benchmark with longer timeout (10 minutes)
        logger.info(f"Running hashcat benchmark with command: {' '.join(cmd)}")
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600  # 10-minute timeout
        )
        
        if result.returncode != 0:
            logger.warning(f"Hashcat benchmark failed with code {result.returncode}: {result.stderr}")
            return {}
            
        # Parse benchmark results
        benchmark_data = {}
        
        # Hashcat 6.2.6 uses a different format for benchmark results
        # Format is: 1:0:1755:6000:10.36:10706290465
        # Where 0 is the hash mode and 10706290465 is hashes/sec
        for line in result.stdout.splitlines():
            # Look for lines with the benchmark format
            if ":" in line and not line.startswith("#"):
                parts = line.split(":")
                if len(parts) >= 6:
                    try:
                        # In the hashcat output, the 2nd part is the hash mode
                        # and the 6th part is the hashes per second
                        hash_id = int(parts[1])
                        speed = int(parts[5])
                        benchmark_data[hash_id] = speed
                    except (ValueError, IndexError) as e:
                        logger.warning(f"Error parsing benchmark line: {line} - {str(e)}")
        
        # If we got results, log them
        if benchmark_data:
            logger.info(f"Benchmark results: {benchmark_data}")
        else:
            logger.warning("No benchmark data extracted from hashcat output")
            logger.debug(f"Hashcat stdout: {result.stdout}")
            
            # Also try to estimate from the output text
            if "H/s" in result.stdout:
                # Try to extract speed from the text output
                matches = re.findall(r'(\d+(?:\.\d+)?)\s*([kMGT]?)H/s', result.stdout)
                if matches:
                    for match in matches:
                        value, unit = match
                        multiplier = 1
                        if unit == 'k': multiplier = 1000
                        elif unit == 'M': multiplier = 1000000
                        elif unit == 'G': multiplier = 1000000000
                        elif unit == 'T': multiplier = 1000000000000
                        
                        speed = int(float(value) * multiplier)
                        benchmark_data[hash_mode] = speed
                        logger.info(f"Extracted speed from text: {speed} H/s for mode {hash_mode}")
                        break
                        
        # If we still don't have data, use reasonable defaults
        if not benchmark_data:
            # Use default values based on common hardware capabilities
            if hash_mode == 0:  # MD5
                benchmark_data[0] = 10000000000  # 10 billion H/s
            elif hash_mode == 100:  # SHA1
                benchmark_data[100] = 5000000000  # 5 billion H/s
            elif hash_mode == 1400:  # SHA256
                benchmark_data[1400] = 2000000000  # 2 billion H/s
            elif hash_mode == 1700:  # SHA512
                benchmark_data[1700] = 1000000000  # 1 billion H/s
            elif hash_mode == 3200:  # bcrypt
                benchmark_data[3200] = 50000  # 50K H/s
            elif hash_mode == 10900:  # Argon2id
                benchmark_data[10900] = 500  # 500 H/s (very slow, which is good for security)
            elif hash_mode == 8900:  # scrypt
                benchmark_data[8900] = 2000  # 2K H/s
            else:
                benchmark_data[hash_mode] = 1000000000  # 1 billion H/s as a safe default
            
            logger.warning(f"Using default hash rate for mode {hash_mode}: {benchmark_data[hash_mode]} H/s")
                
        # Also store speed for common hash types based on this one
        # This is a reasonable approximation if we only benchmark one algorithm
        if len(benchmark_data) == 1:
            bench_mode = list(benchmark_data.keys())[0]
            bench_speed = benchmark_data[bench_mode]
            
            # Estimate other hash speeds based on MD5/SHA1/SHA256
            relative_speeds = {
                0: 1.0,      # MD5 (baseline)
                100: 0.8,    # SHA1 (80% of MD5)
                1400: 0.3,   # SHA256 (30% of MD5)
                1700: 0.15,  # SHA512 (15% of MD5)
                3200: 0.0004, # bcrypt (0.04% of MD5)
                1000: 1.2,   # NTLM (120% of MD5)
                10900: 0.00005, # Argon2id (0.005% of MD5)
                8900: 0.0002   # scrypt (0.02% of MD5)
            }
            
            if bench_mode in relative_speeds:
                base_speed = bench_speed / relative_speeds[bench_mode]
                for mode_id, relative_speed in relative_speeds.items():
                    if mode_id != bench_mode:
                        benchmark_data[mode_id] = int(base_speed * relative_speed)
                        
        return benchmark_data
    
    except subprocess.TimeoutExpired as e:
        logger.warning(f"Hashcat benchmark timed out after {e.timeout} seconds. Using MD5 benchmark only.")
        # Fall back to a quick MD5 benchmark if full benchmark times out
        if hash_mode != 0:
            return run_hashcat_benchmark(0)
        return {}
        
    except Exception as e:
        logger.error(f"Error running hashcat benchmark: {str(e)}")
        return {}


def get_hash_rate(hash_type: str = 'sha256') -> int:
    """Get hash rate for a specific algorithm, using hashcat benchmarks if available.
    
    Args:
        hash_type: The hash algorithm to get the rate for
        
    Returns:
        Hashes per second for the given algorithm
    """
    global _BENCHMARK_CACHE
    
    # Use cached results if they're fresh (less than 24 hours old)
    current_time = time.time()
    if (current_time - _BENCHMARK_CACHE['timestamp'] < _BENCHMARK_CACHE_TIMEOUT and 
            _BENCHMARK_CACHE['results']):
        logger.info(f"Using cached hashcat benchmark from {int(current_time - _BENCHMARK_CACHE['timestamp'])} seconds ago")
    else:
        # Run new benchmark
        logger.info("Running fresh hashcat benchmark")
        benchmark_results = run_hashcat_benchmark()
        
        if benchmark_results:
            _BENCHMARK_CACHE['timestamp'] = current_time
            _BENCHMARK_CACHE['results'] = benchmark_results
            
            # Calculate a reasonable default based on SHA256 or similar
            if HASHCAT_MODES['sha256'] in benchmark_results:
                _BENCHMARK_CACHE['default_hashes_per_second'] = benchmark_results[HASHCAT_MODES['sha256']]
            elif benchmark_results:
                # Just use the first benchmark result if SHA256 isn't available
                first_key = next(iter(benchmark_results))
                _BENCHMARK_CACHE['default_hashes_per_second'] = benchmark_results[first_key]
                
            logger.info(f"Updated benchmark cache with {len(benchmark_results)} algorithms")
        else:
            logger.warning("Benchmark failed, using fallback hash rate")
    
    # Get the hash mode ID for the requested algorithm
    hash_mode = HASHCAT_MODES.get(hash_type.lower(), HASHCAT_MODES['sha256'])
    
    # Return the requested hash rate from cache, or fall back to default
    if hash_mode in _BENCHMARK_CACHE['results']:
        hashes_per_second = _BENCHMARK_CACHE['results'][hash_mode]
        logger.info(f"Using {hash_type} hash rate: {hashes_per_second} hashes/sec")
        return hashes_per_second
    else:
        logger.warning(f"No benchmark data for {hash_type}, using default rate")
        return _BENCHMARK_CACHE['default_hashes_per_second']


def entropy_to_crack_time(entropy: float, hash_type: str = 'sha256') -> float:
    """Convert entropy to estimated crack time.

    Args:
        entropy (float): The entropy value.
        hash_type (str): The hash algorithm to use for estimation.

    Returns:
        float: The estimated crack time in seconds.
    """
    # Use dynamic hash rate from hashcat benchmarking
    hashes_per_second = get_hash_rate(hash_type)
    
    # Use the formula: time = (0.5 * 2^entropy) / hash_rate
    # The 0.5 factor accounts for average time to crack (half the keyspace)
    crack_time = (0.5 * math.pow(2, entropy)) / hashes_per_second
    
    logger.info(f"Password entropy: {entropy} bits, estimated crack time: {crack_time} seconds using {hash_type}")
    return crack_time


def display_time(seconds: float) -> str:
    """ "Convert seconds to a human-readable time representation.

    Args:
        seconds (float): The time in seconds.

    Returns:
        str: The human-readable time representation.
    """
    return (
        "instant"
        if seconds < 1
        else f"{seconds:.2f} seconds"
        if seconds < SECONDS_IN_MINUTE
        else f"{1 + math.ceil(seconds / SECONDS_IN_MINUTE):.2f} minutes"
        if seconds < SECONDS_IN_HOUR
        else f"{1 + math.ceil(seconds / SECONDS_IN_HOUR):.2f} hours"
        if seconds < SECONDS_IN_DAY
        else f"{1 + math.ceil(seconds / SECONDS_IN_DAY):.2f} days"
        if seconds < SECONDS_IN_MONTH
        else f"{1 + math.ceil(seconds / SECONDS_IN_MONTH):.2f} months"
        if seconds < SECONDS_IN_YEAR
        else f"{1 + math.ceil(seconds / SECONDS_IN_YEAR):.2f} years"
        if seconds < SECONDS_IN_CENTURY
        else f"{1 + math.ceil(seconds / SECONDS_IN_CENTURY):.2f} centuries"
        if seconds < 1_00_00_000 * SECONDS_IN_CENTURY
        else "Eternity"
    )


def test_indian_script_support() -> Dict[str, bool]:
    """Test if Indian scripts are properly supported.
    
    This function attempts to create and process a short string in each
    Indian script to verify that they're working correctly.
    
    Returns:
        Dict[str, bool]: Dictionary mapping script names to boolean values
                         indicating whether they're working properly.
    """
    results = {}
    
    for script_name, sample in INDIAN_SCRIPT_SAMPLES.items():
        try:
            # Take first 3 characters as a test sample
            test_sample = sample[:3]
            
            # Verify we can process this sample correctly
            has_non_latin, scripts = detect_scripts(test_sample)
            
            # Script detection should identify this as non-Latin and correctly classify it
            results[script_name] = has_non_latin and (script_name in scripts or any(s in script_name for s in scripts))
            
        except Exception as e:
            # If any exception occurs, the script isn't properly supported
            results[script_name] = False
    
    return results

# Run a quick test when module is loaded to log script support status
try:
    script_support = test_indian_script_support()
    for script, supported in script_support.items():
        if supported:
            logger.info(f"{script} script properly supported")
        else:
            logger.warning(f"{script} script may not be fully supported")
except Exception as e:
    logger.error(f"Error testing script support: {str(e)}")

def assess_password_vulnerability(password: str, strength: float, entropy: float) -> Dict[str, Dict[str, str]]:
    """Assess password vulnerability against different attack types.
    
    Args:
        password (str): The password to assess
        strength (float): The calculated strength value (0-1)
        entropy (float): The calculated entropy value
        
    Returns:
        Dict: Vulnerability assessment for different attack types
    """
    # Analyze password characteristics in detail
    password_length = len(password)
    unique_chars = len(set(password))
    char_diversity_ratio = unique_chars / max(1, password_length)  # Avoid division by zero
    
    # Character composition analysis
    has_lowercase = any(c.islower() for c in password)
    has_uppercase = any(c.isupper() for c in password)
    has_digits = any(c.isdigit() for c in password)
    has_symbols = any(not c.isalnum() for c in password)
    
    # Count different character types
    lowercase_count = sum(1 for c in password if c.islower())
    uppercase_count = sum(1 for c in password if c.isupper())
    digits_count = sum(1 for c in password if c.isdigit())
    symbols_count = sum(1 for c in password if not c.isalnum())
    
    # Calculate character set diversity
    char_type_count = (bool(lowercase_count) + bool(uppercase_count) + 
                       bool(digits_count) + bool(symbols_count))
    
    # Advanced pattern detection
    has_keyboard_sequence = False  # Simplified check, would need more complex logic for full detection
    
    # Common words/patterns 
    common_words = [
        "password", "admin", "welcome", "123456", "qwerty", "letmein", "monkey", 
        "football", "dragon", "baseball", "superman", "batman", "trustno1", "sunshine",
        "iloveyou", "princess", "admin123", "welcome1", "login", "abc123", "qwerty123",
        "123abc", "123123", "12345", "1234", "111111", "123321", "654321", "666666", 
        "696969", "888888", "1234567", "12345678", "87654321"
    ]
    
    # Common substitutions to detect (e.g., 'a' => '@')
    substitutions = {
        'a': '@', 'e': '3', 'i': '1', 'o': '0', 's': '$', 't': '7', 'l': '1',
        'b': '8', 'z': '2'
    }
    
    # Check for common words with possible character substitutions
    password_lower = password.lower()
    
    # Check for direct word matches
    has_common_word_direct = any(word in password_lower for word in common_words)
    
    # Check for substituted words
    has_common_word_substituted = False
    for word in common_words:
        # Create possible variations with substitutions
        variations = [word]
        for char, sub in substitutions.items():
            for i, variation in enumerate(variations.copy()):
                if char in variation:
                    variations.append(variation.replace(char, sub))
        
        # Check if any variation is in the password
        if any(var in password_lower for var in variations):
            has_common_word_substituted = True
            break
    
    has_common_substring = has_common_word_direct or has_common_word_substituted
    
    # Check for repeated characters
    repeated_chars = sum(1 for i in range(1, len(password)) if password[i] == password[i-1])
    repetition_ratio = repeated_chars / max(1, len(password) - 1)
    
    # Check for sequential characters (like "123", "abc")
    sequential_count = 0
    for i in range(1, len(password) - 1):
        # Check for ascending sequences
        if (ord(password[i]) == ord(password[i-1]) + 1 and 
            ord(password[i+1]) == ord(password[i]) + 1):
            sequential_count += 1
        # Check for descending sequences
        elif (ord(password[i]) == ord(password[i-1]) - 1 and 
              ord(password[i+1]) == ord(password[i]) - 1):
            sequential_count += 1
    
    # Get script info to factor into assessment
    has_non_latin, scripts_used = detect_scripts(password)
    uses_multiple_scripts = len(scripts_used) > 1
    
    # Vulnerability levels with detailed descriptions
    risk_levels = {
        "very_high": {
            "risk": "Very High", 
            "description": "Extremely vulnerable to this attack type. This password would likely be compromised within minutes."
        },
        "high": {
            "risk": "High", 
            "description": "Highly vulnerable to this attack type. This password could be compromised within hours."
        },
        "moderate": {
            "risk": "Moderate", 
            "description": "Moderately vulnerable to this attack type. This password might withstand basic attempts but could be compromised with dedicated resources."
        },
        "low": {
            "risk": "Low", 
            "description": "Low vulnerability to this attack type. This password would require significant resources to compromise."
        },
        "very_low": {
            "risk": "Very Low", 
            "description": "Very low vulnerability to this attack type. This password would be extremely difficult to compromise through this method."
        }
    }
    
    # DICTIONARY ATTACK VULNERABILITY
    # ===============================
    # Factors that increase dictionary attack vulnerability:
    # - Presence of common words
    # - Low entropy
    # - Few character types
    # - Short length
    # 
    # Factors that decrease dictionary attack vulnerability:
    # - Use of non-Latin scripts
    # - High character diversity
    # - No common words
    
    if has_common_substring:
        if password_length < 10:
            dictionary_risk = risk_levels["very_high"]
        elif password_length < 14:
            dictionary_risk = risk_levels["high"]
        else:
            dictionary_risk = risk_levels["moderate"]
    elif has_lowercase and password_length < 12 and char_type_count <= 2:
        dictionary_risk = risk_levels["high"]
    elif password_length < 16 and char_type_count <= 3:
        dictionary_risk = risk_levels["moderate"]
    elif password_length >= 16 or char_type_count >= 3:
        if strength < 0.7:
            dictionary_risk = risk_levels["low"]
        else:
            dictionary_risk = risk_levels["very_low"]
    else:
        dictionary_risk = risk_levels["moderate"]
    
    # If using non-Latin scripts, reduce dictionary attack vulnerability
    if has_non_latin:
        if dictionary_risk == risk_levels["very_high"]:
            dictionary_risk = risk_levels["high"]
        elif dictionary_risk == risk_levels["high"]:
            dictionary_risk = risk_levels["moderate"]
        elif dictionary_risk == risk_levels["moderate"]:
            dictionary_risk = risk_levels["low"]
        elif dictionary_risk == risk_levels["low"]:
            dictionary_risk = risk_levels["very_low"]
    
    # BRUTE FORCE ATTACK VULNERABILITY
    # ================================
    # Factors that increase brute force vulnerability:
    # - Short length
    # - Few character types
    # - Low entropy
    #
    # Factors that decrease brute force vulnerability:
    # - Long length
    # - Multiple character types
    # - Use of multiple scripts
    
    # Calculate effective keyspace
    # Each character type expands the keyspace
    keyspace = 0
    if has_lowercase:
        keyspace += 26
    if has_uppercase:
        keyspace += 26
    if has_digits:
        keyspace += 10
    if has_symbols:
        keyspace += 33  # Approximate for common symbols
    if has_non_latin:
        keyspace += 100  # Conservative estimate for non-Latin characters
    
    # Brute force time estimate based on keyspace^length
    if password_length <= 6:
        brute_force_risk = risk_levels["very_high"]
    elif password_length <= 8:
        if char_type_count <= 2:
            brute_force_risk = risk_levels["very_high"]
        else:
            brute_force_risk = risk_levels["high"]
    elif password_length <= 10:
        if char_type_count <= 2:
            brute_force_risk = risk_levels["high"]
        elif char_type_count == 3:
            brute_force_risk = risk_levels["moderate"]
        else:
            brute_force_risk = risk_levels["low"]
    elif password_length <= 12:
        if char_type_count <= 2:
            brute_force_risk = risk_levels["moderate"]
        else:
            brute_force_risk = risk_levels["low"]
    else:  # password_length > 12
        if char_type_count <= 1:
            brute_force_risk = risk_levels["moderate"]
        elif char_type_count == 2:
            brute_force_risk = risk_levels["low"]
        else:
            brute_force_risk = risk_levels["very_low"]
    
    # If using multiple scripts, brute force becomes harder
    if uses_multiple_scripts:
        if brute_force_risk == risk_levels["very_high"]:
            brute_force_risk = risk_levels["high"]
        elif brute_force_risk == risk_levels["high"]:
            brute_force_risk = risk_levels["moderate"]
        elif brute_force_risk == risk_levels["moderate"]:
            brute_force_risk = risk_levels["low"]
        elif brute_force_risk == risk_levels["low"]:
            brute_force_risk = risk_levels["very_low"]
    
    # HYBRID ATTACK VULNERABILITY
    # ==========================
    # Hybrid attacks combine dictionary and brute force methods
    # They're particularly effective against passwords that add simple variations to common words
    
    if has_common_substring:
        if password_length < 10:
            hybrid_risk = risk_levels["very_high"]
        elif password_length < 14:
            hybrid_risk = risk_levels["high"]
        else:
            hybrid_risk = risk_levels["moderate"]
    elif lowercase_count > 0 and (digits_count <= 2 or symbols_count <= 1) and password_length < 12:
        hybrid_risk = risk_levels["high"]
    elif password_length < 14 and char_type_count <= 3:
        hybrid_risk = risk_levels["moderate"]
    elif (password_length >= 14 and char_type_count >= 3) or strength > 0.8:
        hybrid_risk = risk_levels["very_low"]
    else:
        hybrid_risk = risk_levels["low"]
    
    # If using non-Latin scripts, reduce hybrid attack vulnerability
    if has_non_latin:
        if hybrid_risk == risk_levels["very_high"]:
            hybrid_risk = risk_levels["high"]
        elif hybrid_risk == risk_levels["high"]:
            hybrid_risk = risk_levels["moderate"]
        elif hybrid_risk == risk_levels["moderate"]:
            hybrid_risk = risk_levels["low"]
        elif hybrid_risk == risk_levels["low"]:
            hybrid_risk = risk_levels["very_low"]
    
    # RAINBOW TABLE ATTACK VULNERABILITY
    # =================================
    # Rainbow tables are pre-computed tables for reversing cryptographic hash functions
    # They're effective against unsalted hashes of common passwords or simple patterns
    # Special characters and long passwords make rainbow tables less effective
    
    if not (has_symbols or has_non_latin) and password_length < 10:
        if char_type_count <= 2:
            rainbow_risk = risk_levels["very_high"]
        else:
            rainbow_risk = risk_levels["high"]
    elif not (has_symbols or has_non_latin) and password_length < 14:
        rainbow_risk = risk_levels["moderate"]
    elif has_symbols and password_length < 12:
        rainbow_risk = risk_levels["low"]
    else:
        rainbow_risk = risk_levels["very_low"]
    
    # Non-Latin scripts are not typically included in rainbow tables
    if has_non_latin:
        rainbow_risk = risk_levels["very_low"]
    
    # TABLE ATTACK VULNERABILITY
    # =========================
    # Table attacks use tables of common passwords to quickly check against a hash
    # They're most effective against passwords found in breached databases
    
    if has_common_substring and password_length < 10:
        table_risk = risk_levels["very_high"]
    elif has_common_substring and password_length < 14:
        table_risk = risk_levels["high"]
    elif entropy < 40:
        table_risk = risk_levels["moderate"]
    elif entropy < 60:
        table_risk = risk_levels["low"]
    else:
        table_risk = risk_levels["very_low"]
    
    # Non-Latin scripts are not typically included in common password tables
    if has_non_latin:
        if table_risk == risk_levels["very_high"]:
            table_risk = risk_levels["high"]
        elif table_risk == risk_levels["high"]:
            table_risk = risk_levels["moderate"]
        elif table_risk == risk_levels["moderate"]:
            table_risk = risk_levels["low"]
        else:
            table_risk = risk_levels["very_low"]
    
    # Log vulnerability assessment for debugging
    logger.info(f"Password analysis: length={password_length}, diversity={char_diversity_ratio:.2f}, types={char_type_count}")
    logger.info(f"Character counts: lowercase={lowercase_count}, uppercase={uppercase_count}, digits={digits_count}, symbols={symbols_count}")
    logger.info(f"Non-Latin: {has_non_latin}, Scripts: {scripts_used}")
    logger.info(f"Vulnerability assessment: dictionary={dictionary_risk['risk']}, brute={brute_force_risk['risk']}, " +
                f"hybrid={hybrid_risk['risk']}, rainbow={rainbow_risk['risk']}, table={table_risk['risk']}")
    
    return {
        "dictionary_attack": dictionary_risk,
        "brute_force_attack": brute_force_risk,
        "hybrid_attack": hybrid_risk,
        "rainbow_table_attack": rainbow_risk,
        "table_attack": table_risk
    }

def check_rockyou_dataset(password: str) -> Tuple[bool, int]:
    """Check if the password exists in the RockYou dataset.
    
    Args:
        password (str): The password to check
        
    Returns:
        Tuple[bool, int]: A tuple containing:
            - Boolean indicating if the password was found
            - Count of occurrences in the dataset (0 if not found)
    """
    # In a production environment, this would check against the actual RockYou dataset
    # For this implementation, we'll use a small subset of common passwords from the dataset
    
    # Common passwords from RockYou dataset (top entries)
    common_rockyou_passwords = {
        "123456": 290729,
        "12345": 79076,
        "123456789": 59462,
        "password": 59184,
        "iloveyou": 51622,
        "princess": 35231,
        "1234567": 29629,
        "rockyou": 20901,
        "12345678": 20553,
        "abc123": 17542,
        "nicole": 17168,
        "daniel": 16409,
        "babygirl": 16094,
        "monkey": 15294,
        "lovely": 14950,
        "jessica": 14909,
        "654321": 14898,
        "michael": 14329,
        "ashley": 14103,
        "qwerty": 13982,
        "111111": 13844,
        "iloveu": 13621,
        "000000": 13602,
        "michelle": 13492,
        "tigger": 13367,
        "sunshine": 13233,
        "chocolate": 13220,
        "password1": 13170,
        "soccer": 12333,
        "anthony": 12255,
    }
    
    if password in common_rockyou_passwords:
        return True, common_rockyou_passwords[password]
    
    # Check for simple variations (e.g. with numbers appended)
    if any(password.startswith(p) and password[len(p):].isdigit() for p in common_rockyou_passwords):
        return True, 1  # Found a variation
    
    return False, 0


def check_haveibeenpwned(password: str) -> Tuple[bool, int]:
    """Check if the password has been exposed in data breaches using the HIBP API.
    
    Args:
        password (str): The password to check
        
    Returns:
        Tuple[bool, int]: A tuple containing:
            - Boolean indicating if the password was found in breaches
            - Count of breaches (0 if not found)
    """
    try:
        # Calculate SHA-1 hash of the password
        sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        # Use k-anonymity model: only send first 5 chars of hash
        prefix, suffix = sha1_password[:5], sha1_password[5:]
        
        # Query the API with the prefix
        url = f'https://api.pwnedpasswords.com/range/{prefix}'
        response = requests.get(url)
        
        if response.status_code != 200:
            logger.error(f"Error querying HIBP API: {response.status_code}")
            return False, 0
            
        # Parse the response to find the suffix and count
        for line in response.text.splitlines():
            parts = line.split(':')
            if len(parts) == 2 and parts[0] == suffix:
                count = int(parts[1])
                return True, count
                
        return False, 0
    except Exception as e:
        logger.error(f"Error checking HIBP: {str(e)}")
        return False, 0


def check_password_breaches(password: str) -> Dict:
    """Check if the password appears in data breaches.
    
    Args:
        password (str): The password to check
        
    Returns:
        Dict: Information about breach status
    """
    breach_sources = []
    total_breach_count = 0
    
    # Check RockYou dataset
    in_rockyou, rockyou_count = check_rockyou_dataset(password)
    if in_rockyou:
        breach_sources.append("RockYou dataset")
        total_breach_count += rockyou_count
    
    # Check Have I Been Pwned API
    in_hibp, hibp_count = check_haveibeenpwned(password)
    if in_hibp:
        breach_sources.append("Have I Been Pwned database")
        # Avoid double counting if already found in RockYou
        if "RockYou dataset" not in breach_sources:
            total_breach_count += hibp_count
    
    return {
        "is_breached": in_rockyou or in_hibp,
        "breach_count": total_breach_count,
        "in_known_breach": in_hibp,
        "in_rockyou": in_rockyou,
        "rockyou_count": rockyou_count,
        "breach_source": breach_sources
    }

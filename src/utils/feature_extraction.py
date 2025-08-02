"""
Module for password strength calculation.

This module provides a function for calculating the strength of a password
based on certain criteria.
"""
from typing import Any, Optional

import numpy as np
import pandas as pd
from password_strength import PasswordStats
from sklearn.base import BaseEstimator, TransformerMixin
import unicodedata


def calculate_strength(text: str) -> float:
    """
    Calculate the strength of a password.

    Args:
        text (str): The password for which the strength will be calculated.

    Returns:
        float: The strength value of the password.
    """
    return float(PasswordStats(text).strength())


class LenTransform(BaseEstimator, TransformerMixin):  # type: ignore
    """Transformer that calculates the length of the input text."""

    def fit(
        self, X: pd.DataFrame, y: Optional[np.ndarray[np.int64, Any]] = None
    ) -> "LenTransform":
        """Fit the transformer to the data.

        Args:
            X (pd.DataFrame): Input data containing a "password" column.
            y (np.ndarray, optional): Target values. Defaults to None.

        Returns:
            self: Returns an instance of self.
        """
        return self

    def transform(self, X: pd.DataFrame) -> np.ndarray[np.int64, Any]:
        """Transform the input data.

        Args:
            X (pd.DataFrame): Input data containing a "password" column.

        Returns:
            np.ndarray: Transformed data as a 2D NumPy array with one column
            representing the length of each password.
        """
        X["len"] = X["password"].apply(self._lenTransform)
        transformed_X = X["len"].to_numpy()
        return np.array(transformed_X).reshape(-1, 1)

    def _lenTransform(self, text: str) -> int:
        """Calculate the length of the input text.

        Args:
            text (str): Input text (password).

        Returns:
            int: Length of the input text (password).
        """
        return len(text)


class AlphaUCTransform(BaseEstimator, TransformerMixin):  # type: ignore
    """Transformer that calculates the count of uppercase alphabetic characters
    in the input text."""

    def fit(
        self, X: pd.DataFrame, y: Optional[np.ndarray[np.int64, Any]] = None
    ) -> "AlphaUCTransform":
        """Fit the transformer to the data.

        Args:
            X (pd.DataFrame): Input data containing a "password" column.
            y (np.ndarray, optional): Target values. Defaults to None.

        Returns:
            self: Returns an instance of self.
        """
        return self

    def transform(self, X: pd.DataFrame) -> np.ndarray[np.int64, Any]:
        """Transform the input data.

        Args:
            X (pd.DataFrame): Input data containing a "password" column.

        Returns:
            np.ndarray: Transformed data as a 2D NumPy array with one column
            representing the count of uppercase alphabetic characters in each password.
        """
        X["alphaUC"] = X["password"].apply(self._alphaUCTransform)
        transformed_X = X["alphaUC"].to_numpy()
        return np.array(transformed_X).reshape(-1, 1)

    def _alphaUCTransform(self, text: str) -> int:
        """Calculate the count of uppercase alphabetic characters in the input text.

        Args:
            text (str): Input text.

        Returns:
            int: Count of uppercase alphabetic characters in the input text.
        """
        # Handle uppercase letters in any language
        return sum(1 for a in text if a.isupper())


class AlphaLCTransform(BaseEstimator, TransformerMixin):  # type: ignore
    """Transformer that calculates the count of lowercase alphabetic
    characters in the input text."""

    def fit(
        self, X: pd.DataFrame, y: Optional[np.ndarray[np.int64, Any]] = None
    ) -> "AlphaLCTransform":
        """Fit the transformer to the data.

        Args:
            X (pd.DataFrame): Input data containing a "password" column.
            y (np.ndarray, optional): Target values. Defaults to None.

        Returns:
            self: Returns an instance of self.
        """
        return self

    def transform(self, X: pd.DataFrame) -> np.ndarray[np.int64, Any]:
        """Transform the input data.

        Args:
            X (pd.DataFrame): Input data containing a "password" column.

        Returns:
            np.ndarray: Transformed data as a 2D NumPy array with one column
            representing the count of lowercase alphabetic characters in each password.
        """
        X["alphaLC"] = X["password"].apply(self._alphaLCTransform)
        transformed_X = X["alphaLC"].to_numpy()
        return np.array(transformed_X).reshape(-1, 1)

    def _alphaLCTransform(self, text: str) -> int:
        """Calculate the count of lowercase alphabetic characters in the input text.

        Args:
            text (str): Input text.

        Returns:
            int: Count of lowercase alphabetic characters in the input text.
        """
        # Handle lowercase letters in any language
        return sum(1 for a in text if a.islower())


class NumberTransform(BaseEstimator, TransformerMixin):  # type: ignore
    """Transformer that calculates the count of numeric characters in the input text."""

    def fit(
        self, X: pd.DataFrame, y: Optional[np.ndarray[np.int64, Any]] = None
    ) -> "NumberTransform":
        """Fit the transformer to the data.

        Args:
            X (pd.DataFrame): Input data containing a "password" column.
            y (np.ndarray, optional): Target values. Defaults to None.

        Returns:
            self: Returns an instance of self.
        """
        return self

    def transform(self, X: pd.DataFrame) -> np.ndarray[np.int64, Any]:
        """Transform the input data.

        Args:
            X (pd.DataFrame): Input data containing a "password" column.

        Returns:
            np.ndarray: Transformed data as a 2D NumPy array with one column
            representing the count of numeric characters in each password.
        """
        X["number"] = X["password"].apply(self._numberTransform)
        transformed_X = X["number"].to_numpy()
        return np.array(transformed_X).reshape(-1, 1)

    def _numberTransform(self, text: str) -> int:
        """Calculate the count of numeric characters in the input text.

        Args:
            text (str): Input text.

        Returns:
            int: Count of numeric characters in the input text.
        """
        return sum(bool(a.isdecimal()) for a in text)


class SymbolTransform(BaseEstimator, TransformerMixin):  # type: ignore
    """Transformer that calculates the count of special symbol characters in the input text."""

    def fit(
        self, X: pd.DataFrame, y: Optional[np.ndarray[np.int64, Any]] = None
    ) -> "SymbolTransform":
        """Fit the transformer to the data.

        Args:
            X (pd.DataFrame): Input data containing a "password" column.
            y (np.ndarray, optional): Target values. Defaults to None.

        Returns:
            self: Returns an instance of self.
        """
        return self

    def transform(self, X: pd.DataFrame) -> np.ndarray[np.int64, Any]:
        """Transform the input data.

        Args:
            X (pd.DataFrame): Input data containing a "password" column.

        Returns:
            np.ndarray: Transformed data as a 2D NumPy array with one column
            representing the count of special symbol characters in each password.
        """
        X["symbol"] = X["password"].apply(self._symbolTransform)
        transformed_X = X["symbol"].to_numpy()
        return np.array(transformed_X).reshape(-1, 1)

    def _symbolTransform(self, text: str) -> int:
        """Calculate the count of special symbol characters in the input text.

        Args:
            text (str): Input text.

        Returns:
            int: Count of special symbol characters in the input text.
        """
        # Count characters in Symbol and Punctuation Unicode categories
        return sum(1 for a in text if unicodedata.category(a).startswith(('S', 'P')))


class MidCharTransform(BaseEstimator, TransformerMixin):  # type: ignore
    """Transformer that calculates the count of special symbol or
    numeric characters in the middle of the input text."""

    def fit(
        self, X: pd.DataFrame, y: Optional[np.ndarray[np.int64, Any]] = None
    ) -> "MidCharTransform":
        """Fit the transformer to the data.

        Args:
            X (pd.DataFrame): Input data containing a "password" column.
            y (np.ndarray, optional): Target values. Defaults to None.

        Returns:
            self: Returns an instance of self.
        """
        return self

    def transform(self, X: pd.DataFrame) -> np.ndarray[np.int64, Any]:
        """Transform the input data.

        Args:
            X (pd.DataFrame): Input data containing a "password" column.

        Returns:
            np.ndarray: Transformed data as a 2D NumPy array with one column
            representing the count of special symbol or numeric characters
            in the middle of each password.
        """
        X["midChar"] = X["password"].apply(self._midCharTransform)
        transformed_X = X["midChar"].to_numpy()
        return np.array(transformed_X).reshape(-1, 1)

    def _midCharTransform(self, text: str) -> int:
        """Calculate the count of special symbol or numeric
        characters in the middle of the input text.

        Args:
            text (str): Input text.

        Returns:
            int: Count of special symbol or numeric characters in the middle of the input text.
        """
        # Skip if text is too short
        if len(text) <= 2:
            return 0
            
        # Count numeric or symbol/punctuation characters in the middle section of the text
        return sum(
            bool(unicodedata.category(a).startswith('N') or  # Number
                 unicodedata.category(a).startswith('S') or  # Symbol 
                 unicodedata.category(a).startswith('P'))    # Punctuation
            for a in text[1:-1]
        )


class RepCharTransform(BaseEstimator, TransformerMixin):  # type: ignore
    """Transformer that calculates the count of repeated characters in the input text."""

    def fit(
        self, X: pd.DataFrame, y: Optional[np.ndarray[np.int64, Any]] = None
    ) -> "RepCharTransform":
        """Fit the transformer to the data.

        Args:
            X (pd.DataFrame): Input data containing a "password" column.
            y (np.ndarray, optional): Target values. Defaults to None.

        Returns:
            self: Returns an instance of self.
        """
        return self

    def transform(self, X: pd.DataFrame) -> np.ndarray[np.int64, Any]:
        """Transform the input data.

        Args:
            X (pd.DataFrame): Input data containing a "password" column.

        Returns:
            np.ndarray: Transformed data as a 2D NumPy array with one column
            representing the count of repeated characters in each password.
        """
        X["repChar"] = X["password"].apply(self._repCharTransform)
        transformed_X = X["repChar"].to_numpy()
        return np.array(transformed_X).reshape(-1, 1)

    def _repCharTransform(self, text: str) -> int:
        """Calculate the count of repeated characters in the input text.

        Args:
            text (str): Input text.

        Returns:
            int: Count of repeated characters in the input text.
        """
        return len(text) - len(list(set(text)))


class UniqueCharTransform(BaseEstimator, TransformerMixin):  # type: ignore
    """Transformer that calculates the count of unique characters in the input text."""

    def fit(
        self, X: pd.DataFrame, y: Optional[np.ndarray[np.int64, Any]] = None
    ) -> "UniqueCharTransform":
        """Fit the transformer to the data.

        Args:
            X (pd.DataFrame): Input data containing a "password" column.
            y (np.ndarray, optional): Target values. Defaults to None.

        Returns:
            self: Returns an instance of self.
        """
        return self

    def transform(self, X: pd.DataFrame) -> np.ndarray[np.int64, Any]:
        """Transform the input data.

        Args:
            X (pd.DataFrame): Input data containing a "password" column.

        Returns:
            np.ndarray: Transformed data as a 2D NumPy array with one column
            representing the count of unique characters in each password.
        """
        X["uniqueChar"] = X["password"].apply(self._uniqueCharTransform)
        transformed_X = X["uniqueChar"].to_numpy()
        return np.array(transformed_X).reshape(-1, 1)

    def _uniqueCharTransform(self, text: str) -> int:
        """Calculate the count of unique characters in the input text.

        Args:
            text (str): Input text.

        Returns:
            int: Count of unique characters in the input text.
        """
        return len(list(set(text)))


class ConsecAlphaUCTransform(BaseEstimator, TransformerMixin):  # type: ignore
    """Transformer that calculates the count of consecutive uppercase
    alphabetic characters in the input text."""

    def fit(
        self, X: pd.DataFrame, y: Optional[np.ndarray[np.int64, Any]] = None
    ) -> "ConsecAlphaUCTransform":
        """Fit the transformer to the data.

        Args:
            X (pd.DataFrame): Input data containing a "password" column.
            y (np.ndarray, optional): Target values. Defaults to None.

        Returns:
            self: Returns an instance of self.
        """
        return self

    def transform(self, X: pd.DataFrame) -> np.ndarray[np.int64, Any]:
        """Transform the input data.

        Args:
            X (pd.DataFrame): Input data containing a "password" column.

        Returns:
            np.ndarray: Transformed data as a 2D NumPy array with one column
            representing the count of consecutive uppercase alphabetic characters in each password.
        """
        X["consecAlphaUC"] = X["password"].apply(self._consecAlphaUCTransform)
        transformed_X = X["consecAlphaUC"].to_numpy()
        return np.array(transformed_X).reshape(-1, 1)

    def _consecAlphaUCTransform(self, text: str) -> int:
        """Calculate the count of consecutive uppercase alphabetic characters in the input text.

        Args:
            text (str): Input text.

        Returns:
            int: Count of consecutive uppercase alphabetic characters in the input text.
        """
        temp = ""
        nConsecAlphaUC = 0
        for a in text:
            if a.isupper():
                if temp and temp[-1] == a:
                    nConsecAlphaUC += 1
                temp = a
        return nConsecAlphaUC


class ConsecAlphaLCTransform(BaseEstimator, TransformerMixin):  # type: ignore
    """Transformer that calculates the count of consecutive lowercase
    alphabetic characters in the input text."""

    def fit(
        self, X: pd.DataFrame, y: Optional[np.ndarray[np.int64, Any]] = None
    ) -> "ConsecAlphaLCTransform":
        """Fit the transformer to the data.

        Args:
            X (pd.DataFrame): Input data containing a "password" column.
            y (np.ndarray, optional): Target values. Defaults to None.

        Returns:
            self: Returns an instance of self.
        """
        return self

    def transform(self, X: pd.DataFrame) -> np.ndarray[np.int64, Any]:
        """Transform the input data.

        Args:
            X (pd.DataFrame): Input data containing a "password" column.

        Returns:
            np.ndarray: Transformed data as a 2D NumPy array with one column
            representing the count of consecutive lowercase alphabetic characters in each password.
        """
        X["consecAlphaLC"] = X["password"].apply(self._consecAlphaLCTransform)
        transformed_X = X["consecAlphaLC"].to_numpy()
        return np.array(transformed_X).reshape(-1, 1)

    def _consecAlphaLCTransform(self, text: str) -> int:
        """Calculate the count of consecutive lowercase alphabetic characters in the input text.

        Args:
            text (str): Input text.

        Returns:
            int: Count of consecutive lowercase alphabetic characters in the input text.
        """
        temp = ""
        nConsecAlphaLC = 0
        for a in text:
            if a.islower():
                if temp and temp[-1] == a:
                    nConsecAlphaLC += 1
                temp = a
        return nConsecAlphaLC


class ConsecNumberTransform(BaseEstimator, TransformerMixin):  # type: ignore
    """Transformer that calculates the count of consecutive numeric characters in the input text."""

    def fit(
        self, X: pd.DataFrame, y: Optional[np.ndarray[np.int64, Any]] = None
    ) -> "ConsecNumberTransform":
        """Fit the transformer to the data.

        Args:
            X (pd.DataFrame): Input data containing a "password" column.
            y (np.ndarray, optional): Target values. Defaults to None.

        Returns:
            self: Returns an instance of self.
        """
        return self

    def transform(self, X: pd.DataFrame) -> np.ndarray[np.int64, Any]:
        """Transform the input data.

        Args:
            X (pd.DataFrame): Input data containing a "password" column.

        Returns:
            np.ndarray: Transformed data as a 2D NumPy array with one column
            representing the count of consecutive numeric characters in each password.
        """
        X["consecNumber"] = X["password"].apply(self._consecNumberTransform)
        transformed_X = X["consecNumber"].to_numpy()
        return np.array(transformed_X).reshape(-1, 1)

    def _consecNumberTransform(self, text: str) -> int:
        """Calculate the count of consecutive numeric characters in the input text.

        Args:
            text (str): Input text.

        Returns:
            int: Count of consecutive numeric characters in the input text.
        """
        temp = ""
        nConsecNumber = 0
        for a in text:
            if a.isdecimal():
                if temp and temp[-1] == a:
                    nConsecNumber += 1
                temp = a
        return nConsecNumber


class ConsecSymbolTransform(BaseEstimator, TransformerMixin):  # type: ignore
    """Transformer that calculates the count of consecutive special symbol
    characters in the input text."""

    def fit(
        self, X: pd.DataFrame, y: Optional[np.ndarray[np.int64, Any]] = None
    ) -> "ConsecSymbolTransform":
        """Fit the transformer to the data.

        Args:
            X (pd.DataFrame): Input data containing a "password" column.
            y (np.ndarray, optional): Target values. Defaults to None.

        Returns:
            self: Returns an instance of self.
        """
        return self

    def transform(self, X: pd.DataFrame) -> np.ndarray[np.int64, Any]:
        """Transform the input data.

        Args:
            X (pd.DataFrame): Input data containing a "password" column.

        Returns:
            np.ndarray: Transformed data as a 2D NumPy array with one column
            representing the count of consecutive special symbol characters in each password.
        """
        X["consecSymbol"] = X["password"].apply(self._consecSymbolTransform)
        transformed_X = X["consecSymbol"].to_numpy()
        return np.array(transformed_X).reshape(-1, 1)

    def _consecSymbolTransform(self, text: str) -> int:
        """Calculate the count of consecutive special symbol characters in the input text.

        Args:
            text (str): Input text.

        Returns:
            int: Count of consecutive special symbol characters in the input text.
        """
        temp = ""
        nConsecSymbol = 0
        
        for a in text:
            # Check if character is a symbol or punctuation
            is_symbol = unicodedata.category(a).startswith(('S', 'P'))
            
            if is_symbol:
                if temp and unicodedata.category(temp[-1]).startswith(('S', 'P')):
                    nConsecSymbol += 1
                temp = a
            else:
                temp = a
                
        return nConsecSymbol


class SeqAlphaTransform(BaseEstimator, TransformerMixin):  # type: ignore
    """Transformer that calculates the count of sequential alphabetic
    characters in the input text."""

    def fit(
        self, X: pd.DataFrame, y: Optional[np.ndarray[np.int64, Any]] = None
    ) -> "SeqAlphaTransform":
        """Fit the transformer to the data.

        Args:
            X (pd.DataFrame): Input data containing a "password" column.
            y (np.ndarray, optional): Target values. Defaults to None.

        Returns:
            self: Returns an instance of self.
        """
        return self

    def transform(self, X: pd.DataFrame) -> np.ndarray[np.int64, Any]:
        """Transform the input data.

        Args:
            X (pd.DataFrame): Input data containing a "password" column.

        Returns:
            np.ndarray: Transformed data as a 2D NumPy array with one column
            representing the count of sequential alphabetic characters in each password.
        """
        X["seqAlpha"] = X["password"].apply(self._seqAlphaTransform)
        transformed_X = X["seqAlpha"].to_numpy()
        return np.array(transformed_X).reshape(-1, 1)

    def _seqAlphaTransform(self, text: str) -> int:
        """Calculate the count of sequential alphabetic characters in the input text.

        Args:
            text (str): Input text.

        Returns:
            int: Count of sequential alphabetic characters in the input text.
        """
        sAlphas = "abcdefghijklmnopqrstuvwxyz"
        nSeqAlpha = 0
        for s in range(len(sAlphas) - 2):
            sFwd = sAlphas[s : s + 3]
            sRev = sFwd[::-1]
            if sFwd in text.lower() or sRev in text.lower():
                nSeqAlpha += 1
        return nSeqAlpha


class SeqNumberTransform(BaseEstimator, TransformerMixin):  # type: ignore
    """Transformer that calculates the count of sequential numeric characters in the input text."""

    def fit(
        self, X: pd.DataFrame, y: Optional[np.ndarray[np.int64, Any]] = None
    ) -> "SeqNumberTransform":
        """Fit the transformer to the data.

        Args:
            X (pd.DataFrame): Input data containing a "password" column.
            y (np.ndarray, optional): Target values. Defaults to None.

        Returns:
            self: Returns an instance of self.
        """
        return self

    def transform(self, X: pd.DataFrame) -> np.ndarray[np.int64, Any]:
        """Transform the input data.

        Args:
            X (pd.DataFrame): Input data containing a "password" column.

        Returns:
            np.ndarray: Transformed data as a 2D NumPy array with one column
            representing the count of sequential numeric characters in each password.
        """
        X["seqNumber"] = X["password"].apply(self._seqNumberTransform)
        transformed_X = X["seqNumber"].to_numpy()
        return np.array(transformed_X).reshape(-1, 1)

    def _seqNumberTransform(self, text: str) -> int:
        """Calculate the count of sequential numeric characters in the input text.

        Args:
            text (str): Input text.

        Returns:
            int: Count of sequential numeric characters in the input text.
        """
        sNumerics = "01234567890"
        nSeqNumber = 0
        for s in range(len(sNumerics) - 2):
            sFwd = sNumerics[s : s + 3]
            sRev = sFwd[::-1]
            if sFwd in text.lower() or sRev in text.lower():
                nSeqNumber += 1
        return nSeqNumber


class SeqKeyboardTransform(BaseEstimator, TransformerMixin):  # type: ignore
    """Transformer that calculates the count of sequential keyboard characters in the input text."""

    def fit(
        self, X: pd.DataFrame, y: Optional[np.ndarray[np.int64, Any]] = None
    ) -> "SeqKeyboardTransform":
        """Fit the transformer to the data.

        Args:
            X (pd.DataFrame): Input data containing a "password" column.
            y (np.ndarray, optional): Target values. Defaults to None.

        Returns:
            self: Returns an instance of self.
        """
        return self

    def transform(self, X: pd.DataFrame) -> np.ndarray[np.int64, Any]:
        """Transform the input data.

        Args:
            X (pd.DataFrame): Input data containing a "password" column.

        Returns:
            np.ndarray: Transformed data as a 2D NumPy array with one column
            representing the count of sequential keyboard characters in each password.
        """
        X["seqKeyboard"] = X["password"].apply(self._seqKeyboardTransform)
        transformed_X = X["seqKeyboard"].to_numpy()
        return np.array(transformed_X).reshape(-1, 1)

    def _seqKeyboardTransform(self, text: str) -> int:
        """Calculate the count of sequential keyboard characters in the input text.

        Args:
            text (str): Input text.

        Returns:
            int: Count of sequential keyboard characters in the input text.
        """
        sTopRow = "qwertyuiop"
        sHomeRow = "asdfghjkl"
        sBottomRow = "zxcvbnm"
        nKeyboard = 0
        sRows = [sTopRow, sHomeRow, sBottomRow]

        for sRow in sRows:
            for s in range(len(sRow) - 2):
                sFwd = sRow[s : s + 3]
                sRev = sFwd[::-1]
                if sFwd in text.lower() or sRev in text.lower():
                    nKeyboard += 1

        return nKeyboard


class PatternTransform(BaseEstimator, TransformerMixin):  # type: ignore
    """Transformer that detects common patterns in passwords like dates (MMDDYYYY)."""

    def fit(
        self, X: pd.DataFrame, y: Optional[np.ndarray[np.int64, Any]] = None
    ) -> "PatternTransform":
        """Fit the transformer to the data.

        Args:
            X (pd.DataFrame): Input data containing a "password" column.
            y (np.ndarray, optional): Target values. Defaults to None.

        Returns:
            self: Returns an instance of self.
        """
        return self

    def transform(self, X: pd.DataFrame) -> np.ndarray[np.int64, Any]:
        """Transform the input data.

        Args:
            X (pd.DataFrame): Input data containing a "password" column.

        Returns:
            np.ndarray: Transformed data as a 2D NumPy array with one column
            representing pattern detection in each password.
        """
        X["pattern"] = X["password"].apply(self._patternTransform)
        transformed_X = X["pattern"].to_numpy()
        return np.array(transformed_X).reshape(-1, 1)

    def _patternTransform(self, text: str) -> int:
        """Detect common patterns in the password.
        Common patterns include:
        - Date formats (MMDDYYYY or DDMMYYYY)
        - Simple keyboard patterns not caught by keyboard sequence

        Args:
            text (str): Input text.

        Returns:
            int: 1 if pattern detected, otherwise 0.
        """
        try:
            # Check for date patterns (MMDDYYYY or DDMMYYYY)
            if len(text) >= 8:
                # Look for 8 consecutive digits that could be a date
                for i in range(len(text) - 7):
                    segment = text[i:i+8]
                    # Check if all characters in the segment are standard ASCII digits
                    if segment.isdigit():
                        # Safe conversion to integers using only standard digits
                        mm = int(segment[0:2])
                        dd = int(segment[2:4])
                        yyyy = int(segment[4:8])
                        
                        # Check if it looks like a date (MM between 01-12 or DD between 01-31)
                        if ((1 <= mm <= 12 and 1 <= dd <= 31) or 
                            (1 <= dd <= 31 and 1 <= mm <= 12)) and 1900 <= yyyy <= 2099:
                            return 1
            
            # Check for simple keyboard patterns like "qazwsx", "asdfzxcv"
            keyboard_patterns = ["qazwsx", "asdfzxcv", "zxcvbn", "qwertyuiop"]
            for pattern in keyboard_patterns:
                if pattern in text.lower():
                    return 1
                    
            return 0
            
        except Exception as e:
            # If any exception occurs during pattern detection, log it and return 0 (no pattern)
            # This helps prevent transformation failures
            try:
                problematic_chars = [c for c in text if not c.isascii()]
                problematic_info = f"Contains non-ASCII: {problematic_chars}" if problematic_chars else "Unknown issue"
                print(f"Pattern detection error for '{text}': {str(e)}. {problematic_info}")
            except:
                pass
            return 0


class NonLatinTransform(BaseEstimator, TransformerMixin):  # type: ignore
    """Transformer that calculates the count of non-Latin characters in the input text."""

    def fit(
        self, X: pd.DataFrame, y: Optional[np.ndarray[np.int64, Any]] = None
    ) -> "NonLatinTransform":
        """Fit the transformer to the data.

        Args:
            X (pd.DataFrame): Input data containing a "password" column.
            y (np.ndarray, optional): Target values. Defaults to None.

        Returns:
            self: Returns an instance of self.
        """
        return self

    def transform(self, X: pd.DataFrame) -> np.ndarray[np.int64, Any]:
        """Transform the input data.

        Args:
            X (pd.DataFrame): Input data containing a "password" column.

        Returns:
            np.ndarray: Transformed data as a 2D NumPy array with one column
            representing the count of non-Latin characters in each password.
        """
        X["nonLatin"] = X["password"].apply(self._nonLatinTransform)
        transformed_X = X["nonLatin"].to_numpy()
        return np.array(transformed_X).reshape(-1, 1)

    def _nonLatinTransform(self, text: str) -> int:
        """Calculate the count of non-Latin characters in the input text.

        Args:
            text (str): Input text.

        Returns:
            int: Count of non-Latin characters in the input text.
        """
        latin_chars = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
        return sum(1 for char in text if unicodedata.category(char).startswith('L') and char not in latin_chars)

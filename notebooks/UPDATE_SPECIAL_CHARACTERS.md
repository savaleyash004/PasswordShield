# Notebook Updates for Extended Special Characters

The production code has been updated to support an expanded set of special characters in passwords. To maintain consistency between the notebooks and the production code, the following updates should be made when rerunning the notebooks.

## Character Set Changes

The special character set has been expanded from:
```
!@#$%^&*
```

To include:
```
!@#$%^&*. ~()_+={}[]|\:;'"<>/?`,` (and space)
```

## Updates Needed in Notebooks

### 1. In `notebooks/02.3_feature_engineering.ipynb`:

Update the `symbolTransform` function (around line 1000):
```python
def symbolTransform(text: str) -> int:
    """Counts the number of specific symbols in a given text."""
    special_chars = set("!@#$%^&*. ~()_+={}[]|\\:;'\"<>/?`,` ")
    return sum(a in special_chars for a in text)
```

Update the `midCharTransform` function (around line 1200):
```python
def midCharTransform(text: str) -> int:
    """Counts the number of mid characters in a given text."""
    special_chars = set("!@#$%^&*. ~()_+={}[]|\\:;'\"<>/?`,` ")
    return sum(bool(a.isdecimal() or (a in special_chars)) for a in text[1:-1])
```

Update the `consecSymbolTransform` function (around line 2770):
```python
def consecSymbolTransform(text: str) -> int:
    """Counts the number of consecutive symbols in a given text."""
    special_chars = set("!@#$%^&*. ~()_+={}[]|\\:;'\"<>/?`,` ")
    temp = ""
    nConsecSymbol = 0
    for a in text:
        if a in special_chars:
            if temp and temp[-1] == a:
                nConsecSymbol += 1
            temp = a
    return nConsecSymbol
```

### 2. In `notebooks/04_make_pipeline.ipynb`:

Update the `_symbolTransform` method (around line 265):
```python
def _symbolTransform(self, text: str) -> int:
    special_chars = set("!@#$%^&*. ~()_+={}[]|\\:;'\"<>/?`,` ")
    return sum(a in special_chars for a in text)
```

Update the `_midCharTransform` method (around line 285):
```python
def _midCharTransform(self, text: str) -> int:
    special_chars = set("!@#$%^&*. ~()_+={}[]|\\:;'\"<>/?`,` ")
    return sum(
        bool(
            (a.isdecimal() or (a in special_chars))
            and ix > 0
            and ix < len(text) - 1
        )
        for ix, a in enumerate(text)
    )
```

Update the `_consecSymbolTransform` method (around line 450):
```python
def _consecSymbolTransform(self, text: str) -> int:
    special_chars = set("!@#$%^&*. ~()_+={}[]|\\:;'\"<>/?`,` ")
    temp = ""
    nConsecSymbol = 0
    for a in text:
        if a in special_chars:
            if temp and temp[-1] == a:
                nConsecSymbol += 1
            temp = a
    return nConsecSymbol
```

## Impact of These Changes

When the notebooks are rerun with these updates:

1. The feature extraction will recognize all the additional special characters
2. The model will be trained to evaluate passwords containing these characters
3. Visualizations and analyses will reflect the expanded character set
4. The resulting model will be consistent with the production code

## Note on Retraining

After updating the notebooks, you should retrain the model using:

```bash
python -m src.utils.build_model --train
```

This will ensure the production model reflects the expanded special character set. 
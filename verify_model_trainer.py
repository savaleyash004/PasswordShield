"""
Script to verify model_trainer.py imports and basic functionality.
"""

import os
import sys
import importlib.util

def import_file(module_name, file_path):
    """Import a Python file directly."""
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module

# Import the model_trainer module directly
print("Attempting to import model_trainer.py...")
model_trainer_path = os.path.join(
    "env", "lib", "site-packages", "src", "components", "model_trainer.py"
)
model_trainer_module = import_file("model_trainer", model_trainer_path)
print("Successfully imported model_trainer.py!")

# Print information about available models
print(f"\nXGBoost available: {model_trainer_module.XGBOOST_AVAILABLE}")
print(f"LightGBM available: {model_trainer_module.LIGHTGBM_AVAILABLE}")
print(f"CatBoost available: {model_trainer_module.CATBOOST_AVAILABLE}")

# Test model trainer class initialization
try:
    model_trainer = model_trainer_module.ModelTrainer()
    print("\nSuccessfully created ModelTrainer instance!")
    print(f"FilePath config: {model_trainer.filepath_config}")
except Exception as e:
    print(f"\nError creating ModelTrainer instance: {e}")

print("\nVerification complete - all imports are working correctly.") 
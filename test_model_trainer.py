"""
Test script to verify scikit-learn imports and run a simplified model trainer.
"""

import os
import sys
import numpy as np

# Add the paths to ensure proper importing
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

# Import the scikit-learn modules that were causing issues
from sklearn.ensemble import AdaBoostRegressor, RandomForestRegressor
from sklearn.linear_model import LinearRegression
from sklearn.metrics import mean_absolute_error, mean_squared_error, r2_score
from sklearn.neighbors import KNeighborsRegressor
from sklearn.tree import DecisionTreeRegressor

# Import optional gradient boosting models
try:
    import xgboost as xgb
    XGBOOST_AVAILABLE = True
    print("XGBoost is available")
except ImportError:
    XGBOOST_AVAILABLE = False
    print("XGBoost is not available")

try:
    import lightgbm as lgb
    LIGHTGBM_AVAILABLE = True
    print("LightGBM is available")
except ImportError:
    LIGHTGBM_AVAILABLE = False
    print("LightGBM is not available")

try:
    from catboost import CatBoostRegressor
    CATBOOST_AVAILABLE = True
    print("CatBoost is available")
except ImportError:
    CATBOOST_AVAILABLE = False
    print("CatBoost is not available")

def test_models():
    """Create a small dataset and train basic models to ensure everything works."""
    # Create synthetic data
    np.random.seed(42)
    X = np.random.rand(100, 5)
    y = X[:, 0] * 2 + X[:, 1] * 3 - X[:, 2] * 1.5 + X[:, 3] * 0.5 + np.random.normal(0, 0.1, 100)
    
    # Split into train and test
    X_train, X_test = X[:80], X[80:]
    y_train, y_test = y[:80], y[80:]
    
    # Train a linear regression model
    linear_model = LinearRegression()
    linear_model.fit(X_train, y_train)
    
    # Predict and evaluate
    y_pred = linear_model.predict(X_test)
    score = r2_score(y_test, y_pred)
    print(f"Linear Regression R² score: {score:.4f}")
    
    # Train a decision tree
    tree_model = DecisionTreeRegressor(max_depth=5)
    tree_model.fit(X_train, y_train)
    
    # Predict and evaluate
    y_pred = tree_model.predict(X_test)
    score = r2_score(y_test, y_pred)
    print(f"Decision Tree R² score: {score:.4f}")
    
    # Check if XGBoost is available
    if XGBOOST_AVAILABLE:
        xgb_model = xgb.XGBRegressor(n_estimators=100, max_depth=3)
        
        # Split validation data for early stopping
        X_train_subset = X_train[:60]
        y_train_subset = y_train[:60]
        X_val = X_train[60:]
        y_val = y_train[60:]
        
        # Train with early stopping
        xgb_model.fit(
            X_train_subset, y_train_subset,
            eval_set=[(X_val, y_val)],
            early_stopping_rounds=5,
            verbose=False
        )
        
        # Predict and evaluate
        y_pred = xgb_model.predict(X_test)
        score = r2_score(y_test, y_pred)
        print(f"XGBoost R² score: {score:.4f}")

if __name__ == "__main__":
    print("Testing scikit-learn imports and model training...")
    
    # Print versions
    import sklearn
    print(f"scikit-learn version: {sklearn.__version__}")
    
    if XGBOOST_AVAILABLE:
        import xgboost
        print(f"xgboost version: {xgboost.__version__}")
    
    if LIGHTGBM_AVAILABLE:
        import lightgbm
        print(f"lightgbm version: {lightgbm.__version__}")
    
    if CATBOOST_AVAILABLE:
        import catboost
        print(f"catboost version: {catboost.__version__}")
    
    # Run model tests
    test_models() 
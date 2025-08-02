"""
Test script to verify scikit-learn imports.
"""

try:
    print("Testing scikit-learn imports...")
    
    # Import the packages that are raising errors
    from sklearn.ensemble import AdaBoostRegressor, RandomForestRegressor
    from sklearn.linear_model import LinearRegression
    from sklearn.metrics import mean_absolute_error, mean_squared_error, r2_score
    from sklearn.neighbors import KNeighborsRegressor
    from sklearn.tree import DecisionTreeRegressor
    
    print("All scikit-learn imports successful!")
    
    # Print the versions
    import sklearn
    print(f"scikit-learn version: {sklearn.__version__}")
    
except ImportError as e:
    print(f"Import error: {e}")
except Exception as e:
    print(f"Error: {e}") 
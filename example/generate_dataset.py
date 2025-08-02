"""Generate dataset"""

# Import the DataPusher class and utility functions
from src.api.utils import (
    calc_class_strength,
    calc_entropy,
    display_time,
    entropy_to_crack_time,
)
from src.components.data_pusher import DataPusher

# Create an instance of the DataPusher class
data_pusher = DataPusher()

# Fetch data from MongoDB using DataPusher
df = data_pusher.get_data_from_mongodb()

# Calculate password length, class strength, entropy, crack time, and crack time in seconds
df["length"] = df["password"].apply(len)
df["class_strength"] = df["strength"].apply(calc_class_strength)
df["entropy"] = df["password"].apply(calc_entropy)
df["crack_time_sec"] = df["entropy"].apply(entropy_to_crack_time)
df["crack_time"] = df["crack_time_sec"].apply(display_time)

# Print the first few rows of the DataFrame, its info, and summary statistics
print(df.head())
print(df.info())
print(df.describe())

# Save the DataFrame to a CSV file
df.to_csv("example/data/dataset.csv", index=False)

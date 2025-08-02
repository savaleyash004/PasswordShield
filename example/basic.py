"""Interactive program to calculate password strength using a pipeline."""

from src.interface.config import CustomData
from src.pipe.pipeline import Pipeline


def main():
    """Main function for the interactive program."""
    pipeline = Pipeline()
    custom_data = CustomData()

    while True:
        data = str(input("Enter the password (or 'exit' to quit): "))

        if data.lower() == "exit":
            print("Exiting the program.")
            break

        password = custom_data.data2df(data)
        strength = pipeline.predict(password)
        value = custom_data.array2data(strength)
        print(f"\nPassword: {data} Strength: {value}")


if __name__ == "__main__":
    main()

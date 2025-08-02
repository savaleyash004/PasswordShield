"""Build Pipeline"""
from src.pipe.pipeline import Pipeline

if __name__ == "__main__":
    pipeline = Pipeline()
    pipeline.push_data()
    pipeline.train()

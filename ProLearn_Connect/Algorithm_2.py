import os
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import KBinsDiscretizer

# Specify the folder containing the Excel (.xlsx) files and output path
folder_path = '/folder_path' # replace with your folder path where you have stored your Excel files
output_file_path = '/folder_path/top_videos_summary.xlsx' # replace with your folder path where you want Save your output file and add the file name with .xlsx format after that

# List to store the best video details from each file
top_videos = []

# Get all Excel files from the folder
all_files = [os.path.join(folder_path, f) for f in os.listdir(folder_path) if f.endswith('.xlsx')]

for file in all_files:
    # Step 1: Load the Excel file and preprocess the data
    df = pd.read_excel(file, skiprows=3)  # Skip the first 3 irrelevant rows
    df.columns = ['Title', 'Channel', 'Published At', 'Views', 'Likes', 'Positive Comments',
                  'Subscriber Count', 'Engagement Score', 'Recency Score', 'Duration Score',
                  'Subscriber Score', 'Final Score', 'Video URL', 'ID']

    # Add a column to store the file name without extension
    file_name_without_extension = os.path.splitext(os.path.basename(file))[0]
    df['keywords'] = file_name_without_extension

    # Step 2: Discretize Final Score into categories (e.g., low, medium, high)
    discretizer = KBinsDiscretizer(n_bins=3, encode='ordinal', strategy='uniform')
    df['final_score_category'] = discretizer.fit_transform(df[['Final Score']])

    # Step 3: Define features and target for MNL model
    X = df[['Engagement Score', 'Recency Score', 'Duration Score', 'Subscriber Score']]
    y = df['final_score_category']

    # Step 4: Initialize and train the multinomial logistic regression model
    logistic_reg = LogisticRegression(multi_class='multinomial', solver='lbfgs', max_iter=200)
    logistic_reg.fit(X, y)

    # Step 5: Predict the final score category for all videos in the file
    df['predicted_category'] = logistic_reg.predict(X)

    # Step 6: Find the best video in this file (highest predicted category)
    best_video = df.loc[df['predicted_category'].idxmax()]

    # Append the best video's details to the list
    top_videos.append({

        'Title': best_video['Title'],
        'Channel': best_video['Channel'],

        'Video URL': best_video['Video URL'],
        'ID': best_video['ID'],

    })

# Step 7: Convert the top videos list into a DataFrame and export to Excel
top_videos_df = pd.DataFrame(top_videos)
top_videos_df.to_excel(output_file_path, index=False)

print(f"Summary of top videos has been saved to: {output_file_path}")

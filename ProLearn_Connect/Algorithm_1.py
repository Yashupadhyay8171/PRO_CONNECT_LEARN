import requests
import json
from textblob import TextBlob
from datetime import datetime
import pandas as pd
from openpyxl import Workbook

API_KEY = "AIzaSyCzKoole-Ec-6WZiNLcHKrb39RZ_SzmknM" # Youtube API
BASE_VIDEO_URL = "https://www.youtube.com/watch?v="

def get_video_statistics(video_ids):
    url = f"https://www.googleapis.com/youtube/v3/videos?part=statistics,contentDetails,snippet&id={','.join(video_ids)}&key={API_KEY}"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error fetching video statistics: {response.status_code}")
        return None

def get_channel_subscriber_count(channel_id):
    url = f"https://www.googleapis.com/youtube/v3/channels?part=statistics&id={channel_id}&key={API_KEY}"
    response = requests.get(url)
    if response.status_code == 200:
        data = json.loads(response.text)
        if 'items' in data and len(data['items']) > 0:
            return int(data['items'][0]['statistics'].get('subscriberCount', 0))
        else:
            return 0
    else:
        print(f"Error fetching channel info: {response.status_code}")
        return 0

def get_positive_comments(video_id):
    comments_url = f"https://www.googleapis.com/youtube/v3/commentThreads?part=snippet&videoId={video_id}&key={API_KEY}"
    response = requests.get(comments_url)
    if response.status_code == 200:
        data = json.loads(response.text)
        positive_comments = 0
        if 'items' in data:
            for item in data['items']:
                comment_text = item['snippet']['topLevelComment']['snippet']['textDisplay']
                sentiment = TextBlob(comment_text).sentiment
                if sentiment.polarity > 0:
                    positive_comments += 1
        return positive_comments
    else:
        print(f"Error fetching comments for video {video_id}: {response.status_code}")
        return 0

def calculate_recency(published_at):
    published_date = datetime.strptime(published_at, '%Y-%m-%dT%H:%M:%SZ')
    days_old = (datetime.utcnow() - published_date).days
    b = (days_old) / 365
    if b > 0 and b < 7 :
        return b
    else :
      return 0

def calculate_duration(duration):
    duration = duration.replace('PT', '').replace('H', ' ').replace('M', ' ').replace('S', '')
    duration_parts = list(map(int, duration.split()))

    total_seconds = 0
    if len(duration_parts) == 3:
        total_seconds = duration_parts[0] * 3600 + duration_parts[1] * 60 + duration_parts[2]
    elif len(duration_parts) == 2:
        total_seconds = duration_parts[0] * 60 + duration_parts[1]
    elif len(duration_parts) == 1:
        total_seconds = duration_parts[0]

    if total_seconds < 420:
        return -0.5
    elif total_seconds > 2400:
        return -0.5
    else:
        return 1

def export_to_excel(videos, keywords):
    # Create a DataFrame from the list of videos
    df = pd.DataFrame(videos)
    filename = f"{keywords}.xlsx"

    # Create a writer object and add the DataFrame to the Excel file
    with pd.ExcelWriter(filename, engine='openpyxl') as writer:
        # Create a new worksheet
        workbook = writer.book
        worksheet = workbook.create_sheet('Videos')


        # Write the DataFrame (video data) below the keywords
        df.to_excel(writer, index=False, sheet_name='Videos')

    print(f"Results with keywords '{keywords}' have been exported to {keywords}")

def youtube_search(keywords):
    url = f"https://www.googleapis.com/youtube/v3/search?part=snippet&q={keywords}&type=video&key={API_KEY}"
    response = requests.get(url)

    if response.status_code == 200:
        data = json.loads(response.text)
        if 'items' in data:
            video_ids = [item['id']['videoId'] for item in data['items']]
            stats_data = get_video_statistics(video_ids)

            if stats_data:
                videos = []

                for item in stats_data['items']:
                    video_id = item['id']
                    channel_id = item['snippet']['channelId']
                    stats = item['statistics']
                    view_count = int(stats.get('viewCount', 0))
                    like_count = int(stats.get('likeCount', 0))
                    positive_comments = get_positive_comments(video_id)
                    duration = item['contentDetails']['duration']
                    published_at = next((video['snippet']['publishedAt'] for video in data['items'] if video['id']['videoId'] == video_id), "N/A")
                    channel_name = item['snippet']['channelTitle']

                    subscriber_count = get_channel_subscriber_count(channel_id)

                    recency_score = calculate_recency(published_at)
                    duration_score = calculate_duration(duration)

                    if view_count > 0:
                        engagement_score = (like_count + positive_comments) / view_count
                    else:
                        engagement_score = 0

                    subscriber_score = (subscriber_count ** 0.2) / 10 if subscriber_count > 0 else 0

                    final_score = (0.40 * engagement_score) + (0.2 * recency_score) + (0.1 * duration_score) + (0.3 * subscriber_score)

                    videos.append({
                        'Title': next((video['snippet']['title'] for video in data['items'] if video['id']['videoId'] == video_id), "N/A"),
                        'Channel': channel_name,
                        'Published At': published_at,
                        'Views': view_count,
                        'Likes': like_count,
                        'Positive Comments': positive_comments,
                        'Subscriber Count': subscriber_count,
                        'Engagement Score': engagement_score,
                        'Recency Score': recency_score,
                        'Duration Score': duration_score,
                        'Subscriber Score': subscriber_score,
                        'Final Score': final_score,
                        'Video URL': BASE_VIDEO_URL + video_id,
                        'ID': "5.1.4"
                    })

                videos.sort(key=lambda x: x['Final Score'], reverse=True)
                top_videos = videos[:5]

                for video in top_videos:
                    print(f"Title: {video['Title']}")
                    print(f"Channel: {video['Channel']}")
                    print(f"Published: {video['Published At']}")
                    print(f"Views: {video['Views']}, Likes: {video['Likes']}, Positive Comments: {video['Positive Comments']}")
                    print(f"Subscribers: {video['Subscriber Count']}")
                    print(f"Engagement Score: {video['Engagement Score']:.2f}, Recency Score: {video['Recency Score']:.2f}, Duration Score: {video['Duration Score']:.2f}, Subscriber Score: {video['Subscriber Score']:.2f}")
                    print(f"Final Score: {video['Final Score']:.2f}")
                    print(f"Video URL: {video['Video URL']}")
                    print("-" * 40)

                # Export the results to Excel, with keywords as heading
                export_to_excel(top_videos, keywords)

            else:
                print("Failed to retrieve video statistics.")
        else:
            print("No results found.")
    else:
        print(f"Error: {response.status_code}")

if __name__ == "__main__":
    keywords = input("Enter keywords: ")
    youtube_search(keywords)

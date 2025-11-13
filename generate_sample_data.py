#!/usr/bin/env python3
"""
Generate a sample data.json file for Conan OSINT tool.
This creates a minimal set of popular websites for testing purposes.
"""

import json

def generate_sample_data():
    """Generate sample website data for testing."""

    websites = [
        {
            "name": "GitHub",
            "base_url": "https://github.com/{}",
            "url_probe": "https://github.com/{}",
            "follow_redirects": True,
            "errorType": "status_code",
            "errorMsg": None,
            "errorCode": None,
            "response_url": None,
            "user_agent": None,
            "cookies": None
        },
        {
            "name": "Twitter",
            "base_url": "https://twitter.com/{}",
            "url_probe": "https://twitter.com/{}",
            "follow_redirects": True,
            "errorType": "status_code",
            "errorMsg": None,
            "errorCode": None,
            "response_url": None,
            "user_agent": None,
            "cookies": None
        },
        {
            "name": "Instagram",
            "base_url": "https://www.instagram.com/{}",
            "url_probe": "https://www.instagram.com/{}",
            "follow_redirects": True,
            "errorType": "status_code",
            "errorMsg": None,
            "errorCode": None,
            "response_url": None,
            "user_agent": None,
            "cookies": None
        },
        {
            "name": "Reddit",
            "base_url": "https://www.reddit.com/user/{}",
            "url_probe": "https://www.reddit.com/user/{}",
            "follow_redirects": True,
            "errorType": "status_code",
            "errorMsg": None,
            "errorCode": None,
            "response_url": None,
            "user_agent": None,
            "cookies": None
        },
        {
            "name": "LinkedIn",
            "base_url": "https://www.linkedin.com/in/{}",
            "url_probe": "https://www.linkedin.com/in/{}",
            "follow_redirects": True,
            "errorType": "status_code",
            "errorMsg": None,
            "errorCode": None,
            "response_url": None,
            "user_agent": None,
            "cookies": None
        },
        {
            "name": "YouTube",
            "base_url": "https://www.youtube.com/@{}",
            "url_probe": "https://www.youtube.com/@{}",
            "follow_redirects": True,
            "errorType": "status_code",
            "errorMsg": None,
            "errorCode": None,
            "response_url": None,
            "user_agent": None,
            "cookies": None
        },
        {
            "name": "TikTok",
            "base_url": "https://www.tiktok.com/@{}",
            "url_probe": "https://www.tiktok.com/@{}",
            "follow_redirects": True,
            "errorType": "status_code",
            "errorMsg": None,
            "errorCode": None,
            "response_url": None,
            "user_agent": None,
            "cookies": None
        },
        {
            "name": "Facebook",
            "base_url": "https://www.facebook.com/{}",
            "url_probe": "https://www.facebook.com/{}",
            "follow_redirects": True,
            "errorType": "status_code",
            "errorMsg": None,
            "errorCode": None,
            "response_url": None,
            "user_agent": None,
            "cookies": None
        },
        {
            "name": "Pinterest",
            "base_url": "https://www.pinterest.com/{}",
            "url_probe": "https://www.pinterest.com/{}",
            "follow_redirects": True,
            "errorType": "status_code",
            "errorMsg": None,
            "errorCode": None,
            "response_url": None,
            "user_agent": None,
            "cookies": None
        },
        {
            "name": "Twitch",
            "base_url": "https://www.twitch.tv/{}",
            "url_probe": "https://www.twitch.tv/{}",
            "follow_redirects": True,
            "errorType": "status_code",
            "errorMsg": None,
            "errorCode": None,
            "response_url": None,
            "user_agent": None,
            "cookies": None
        },
        {
            "name": "Medium",
            "base_url": "https://medium.com/@{}",
            "url_probe": "https://medium.com/@{}",
            "follow_redirects": True,
            "errorType": "status_code",
            "errorMsg": None,
            "errorCode": None,
            "response_url": None,
            "user_agent": None,
            "cookies": None
        },
        {
            "name": "Snapchat",
            "base_url": "https://www.snapchat.com/add/{}",
            "url_probe": "https://www.snapchat.com/add/{}",
            "follow_redirects": True,
            "errorType": "status_code",
            "errorMsg": None,
            "errorCode": None,
            "response_url": None,
            "user_agent": None,
            "cookies": None
        }
    ]

    data = {
        "websites": websites
    }

    return data

def main():
    """Main function to generate and save sample data."""
    print("🔧 Generating sample data.json...")

    data = generate_sample_data()

    output_file = "src/data.json"

    with open(output_file, "w") as f:
        json.dump(data, f, indent=2)

    print(f"✅ Generated {output_file} with {len(data['websites'])} websites")
    print("\nIncluded websites:")
    for site in data['websites']:
        print(f"  - {site['name']}")

    print("\n⚠️  Note: This is a minimal test dataset.")
    print("   For a complete dataset, use the original data.json from GoSearch repository:")
    print("   https://github.com/ibnaleem/gosearch")

if __name__ == "__main__":
    main()

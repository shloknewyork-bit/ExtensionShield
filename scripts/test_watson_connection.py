#!/usr/bin/env python3
"""
Test script to verify WatsonX (IBM Watson) connection and API key configuration.

This script checks:
1. Required environment variables are set
2. Watson client can be initialized
3. A simple test call can be made to verify authentication
"""

import os
import sys
from pathlib import Path

# Add the src directory to the path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

def check_env_vars():
    """Check if required Watson environment variables are set."""
    print("=" * 60)
    print("Checking WatsonX Environment Variables")
    print("=" * 60)
    
    required_vars = {
        "WATSONX_API_KEY": os.getenv("WATSONX_API_KEY"),
        "WATSONX_PROJECT_ID": os.getenv("WATSONX_PROJECT_ID"),
        "WATSONX_API_ENDPOINT": os.getenv("WATSONX_API_ENDPOINT"),
    }
    
    optional_vars = {
        "LLM_PROVIDER": os.getenv("LLM_PROVIDER", "watsonx (default)"),
        "LLM_MODEL": os.getenv("LLM_MODEL", "meta-llama/llama-3-3-70b-instruct (default)"),
    }
    
    all_set = True
    for var_name, var_value in required_vars.items():
        if var_value:
            # Mask the API key for security
            if "API_KEY" in var_name:
                masked_value = var_value[:8] + "..." + var_value[-4:] if len(var_value) > 12 else "***"
                print(f"✅ {var_name}: {masked_value}")
            else:
                print(f"✅ {var_name}: {var_value}")
        else:
            print(f"❌ {var_name}: NOT SET")
            all_set = False
    
    print("\nOptional Configuration:")
    for var_name, var_value in optional_vars.items():
        print(f"   {var_name}: {var_value}")
    
    print()
    return all_set, required_vars

def test_watson_connection(api_key: str, project_id: str, endpoint: str, model: str = None):
    """Test Watson connection by making a simple API call."""
    print("=" * 60)
    print("Testing WatsonX Connection")
    print("=" * 60)
    
    try:
        from langchain_ibm import ChatWatsonx
        
        # Use default model if not specified
        if not model:
            model = os.getenv("LLM_MODEL", "meta-llama/llama-3-3-70b-instruct")
        
        print(f"Initializing WatsonX client...")
        print(f"  Model: {model}")
        print(f"  Endpoint: {endpoint}")
        print(f"  Project ID: {project_id}")
        
        # Initialize the client
        client = ChatWatsonx(
            url=endpoint,
            project_id=project_id,
            apikey=api_key,
            model_id=model,
            params={
                "max_new_tokens": 50,
                "temperature": 0.1,
            }
        )
        
        print("\n✅ WatsonX client initialized successfully!")
        
        # Make a simple test call
        print("\nMaking test API call...")
        response = client.invoke("Say 'Hello' in one word.")
        
        print(f"✅ Connection successful!")
        print(f"\nResponse: {response.content}")
        
        return True, None
        
    except ImportError as e:
        error_msg = f"Failed to import langchain_ibm: {e}\nPlease install it with: pip install langchain-ibm"
        print(f"❌ {error_msg}")
        return False, error_msg
        
    except Exception as e:
        error_str = str(e)
        error_msg = f"Connection failed: {error_str}"
        print(f"❌ {error_msg}")
        
        # Provide helpful error messages
        if "401" in error_str or "unauthorized" in error_str.lower() or "authentication" in error_str.lower():
            print("\n💡 Authentication Error - Possible issues:")
            print("   - Invalid API key")
            print("   - API key doesn't have access to WatsonX")
            print("   - Check your API key at: https://cloud.ibm.com/iam/apikeys")
        elif "404" in error_str or "not found" in error_str.lower():
            print("\n💡 Not Found Error - Possible issues:")
            print("   - Invalid project ID")
            print("   - Project doesn't exist or you don't have access")
            print("   - Check your project at: https://dataplatform.cloud.ibm.com")
        elif "invalid_instance_status" in error_str.lower() or ("inactive" in error_str.lower() and "wml" in error_str.lower()):
            print("\n💡 WML Instance Status Error - This is the issue!")
            print("   Your WML instance is associated but is currently INACTIVE.")
            print("\n   To fix this:")
            print("   1. Go to IBM Cloud: https://cloud.ibm.com")
            print("   2. Navigate to your Watson Machine Learning service instance")
            print("   3. Activate/Start the service instance")
            print("   4. Wait a few minutes for it to become active")
            print("\n   The instance needs to be in 'Active' status to use WatsonX models.")
        elif "no_associated_service_instance" in error_str.lower() or "wml instance" in error_str.lower():
            print("\n💡 WML Instance Error - This is the issue!")
            print("   Your WatsonX project is not associated with a Watson Machine Learning (WML) instance.")
            print("\n   To fix this:")
            print("   1. Go to IBM Cloud: https://cloud.ibm.com")
            print("   2. Create a Watson Machine Learning service instance:")
            print("      - Catalog → AI/Machine Learning → Watson Machine Learning")
            print("      - Create a new instance (Lite plan is free)")
            print("   3. Associate your WatsonX project with the WML instance:")
            print("      - Go to: https://dataplatform.cloud.ibm.com")
            print("      - Open your WatsonX project")
            print("      - Go to Settings → Services")
            print("      - Add your WML service instance to the project")
            print("\n   After associating, wait a few minutes and try again.")
        elif "endpoint" in error_str.lower() or "url" in error_str.lower():
            print("\n💡 Endpoint Error - Possible issues:")
            print("   - Invalid API endpoint URL")
            print("   - Endpoint doesn't match your region")
            print("   - Common endpoints:")
            print("     - US South: https://us-south.ml.cloud.ibm.com")
            print("     - EU: https://eu-de.ml.cloud.ibm.com")
            print("     - UK: https://eu-gb.ml.cloud.ibm.com")
        elif "model" in error_str.lower():
            print("\n💡 Model Error - Possible issues:")
            print("   - Model not available in your project")
            print("   - Invalid model name")
            print("   - Check available models in your WatsonX project")
        
        return False, error_msg

def main():
    """Main function to run all checks."""
    print("\n" + "=" * 60)
    print("WatsonX Connection Test")
    print("=" * 60 + "\n")
    
    # Check environment variables
    all_set, env_vars = check_env_vars()
    
    if not all_set:
        print("\n❌ Missing required environment variables!")
        print("\nPlease set the following in your .env file:")
        print("  WATSONX_API_KEY=your-api-key")
        print("  WATSONX_PROJECT_ID=your-project-id")
        print("  WATSONX_API_ENDPOINT=https://us-south.ml.cloud.ibm.com")
        print("\nOr set them as environment variables.")
        return 1
    
    # Test connection
    model = os.getenv("LLM_MODEL", "meta-llama/llama-3-3-70b-instruct")
    success, error = test_watson_connection(
        api_key=env_vars["WATSONX_API_KEY"],
        project_id=env_vars["WATSONX_PROJECT_ID"],
        endpoint=env_vars["WATSONX_API_ENDPOINT"],
        model=model
    )
    
    print("\n" + "=" * 60)
    if success:
        print("✅ WatsonX connection test PASSED!")
        print("=" * 60)
        return 0
    else:
        print("❌ WatsonX connection test FAILED!")
        print("=" * 60)
        if error:
            print(f"\nError details: {error}")
        return 1

if __name__ == "__main__":
    sys.exit(main())


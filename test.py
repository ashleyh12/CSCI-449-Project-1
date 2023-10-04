import automate.py 
import unittest
import requests
from unittest.mock import MagicMock, patch


class locTest(test.locTestCases):
  def test_location(self, mock_request):
        # Mocking the response from  requests.get 
        mock_response = MagicMock()
        mock_response.json.return_value = 
        {
            'ip': '987.654.321.0',
            'longitude': 87.738,
            'latitude': -109.243,
            'city': 'Sample City'
        }


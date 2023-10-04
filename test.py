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

        mock_requests.return_value = mock_response
    
        # Here we are calling the function found in automate.py (getLocation)
        result = getLocation()

        # inputting values from above into an expected result
        expected_result = ('987.654.321.0', (87.738, -109.243), 'Sample City')

        # Making sure that the result corresponds to the expected result we have above
        self.assertEqual(result, expected_result)

    @patch('requests.get')

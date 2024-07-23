import requests

def ocr_space_api(file_path, overlay=False, api_key='K87236353188957', language='eng'):
    """
    OCR.space API request with local file.
    :param file_path: The path to the image/PDF file.
    :param overlay: Boolean flag to include text overlay in response.
    :param api_key: OCR.space API key.
    :param language: Language code to use for OCR.
    :return: Result in JSON format.
    """
    payload = {
        'isOverlayRequired': overlay,
        'apikey': api_key,
        'language': language,
    }
    with open(file_path, 'rb') as f:
        r = requests.post('https://api.ocr.space/parse/image',
                          files={file_path: f},
                          data=payload,
                          )
    return r.json()

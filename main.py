import requests

def main():
    while True:
        cve = input("Введите CVE (или 'q' для выхода): ")
        if cve.lower() == 'q':
            break
        
        url = f'https://access.redhat.com/api/v2/security/cve/CVE-{cve}?lang=en'
        try:
            response = requests.get(url)
            response.raise_for_status()
            data = response.json()

            # Извлечение значения CVSS и даты публикации
            cvss_score = data['data'].get('field_cve_cvss3_base_score', 'Не указано')
            if isinstance(cvss_score, dict):
                cvss_score = cvss_score.get('value', 'Не указано')

            cve_publicted = data['data'].get('field_cve_public_date', {}).get('value', 'Не указано')

            # Извлечение списка объектов и поиск состояния для нужного продукта
            releases = data.get('data', {}).get('field_cve_releases_txt', {}).get('object', [])
            state = 'no info'
            rhsa_name = 'no info'
            url_rhsa = 'no info'

            for release in releases:
                if isinstance(release, dict):
                    advisory = release.get('advisory', {})
                    if advisory.get('name') and advisory.get('url'):
                        if release.get('product') == 'Red Hat Enterprise Linux 9':
                            state = release.get('state', 'Не указано')
                            rhsa_name = advisory.get('name', 'Не указано')
                            url_rhsa = advisory.get('url', 'Не указан')
                            break
            else:
                print("Product 'Red Hat Enterprise Linux 9' not found.")

            print(cvss_score, ' ', cve_publicted, ' ', state, ' ', rhsa_name, '\n', url_rhsa)
        except requests.RequestException as e:
            print(f"Error while making request: {e}")
        except KeyError as e:
            print(f"Error data: {e}")
        except TypeError as e:
            print(f"Error type: {e}")

if __name__ == '__main__':
    main()

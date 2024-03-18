import requests as re
import argparse
import os
import json
import csv

VALNURS_SEARCH_API = 'https://vulners.com/api/v3/burp/softwareapi'


def get_software_info(software: str, version: str, api_key: str) -> dict:
    headers = {"Content-Type" : "application/json"}
    result = {
        'software': software,
        'version': version,
        'cve_info': []
    }
    
    data = {
        "software": software,
        "version": version,
        "type": "software", 
        "maxVulnerabilities": 10,
        "apiKey": f"{api_key}"
    }

    response = re.post(VALNURS_SEARCH_API, headers=headers, json=data)
    if response.status_code != 200:
        print(f"Valnurs вернул код {response.status_code}")
        print(response.json())
        exit(1)

    result_dict = response.json()
    data = result_dict.get('data')
    
    if data == None:
        return result
    
    search = data.get('search')
    if search == None:
        return result
    

    for r in search:
        cve_info = {
            'cve': r['_source']['cvelist'],
            'link': r['_source']['href'] if r['_source']['href'] != '' else "-"
        }
        result['cve_info'].append(cve_info)

    return result

def analizy_software_list(software_list: list, api_key: str) -> list:
    result = []
    
    for sw in software_list:
        print(f"Производится анализ {sw['Program']} версии {sw['Version']}")
        res = get_software_info(sw['Program'], sw['Version'],  api_key)
        if len(res['cve_info']) > 0:
            count = sum(len(s) for s in res['cve_info'])
            print(f"Обнаружено {count} уязвимостей")
        else:
            print(f"Уязвимостей не обнаружено")
        result.append(res)
    
    return result

def main(args: any) -> None:
    api_key = args.api_key
    file = args.file
    output_file = args.output_file
    
    if api_key == None:
        api_key = os.getenv("VALNURS_API_KEY")

    if api_key == '':
        print("Api-key не может быть пустым. Используйте флаг -k или переменную VALNURS_API_KEY")
        exit(1)
        
    print("Файл с перечнем ПО для проверки: " + file)
    
    with open(file, 'rb') as f:
        software_list = json.load(f)
        
    print("Начинается анализ списка ПО")
    result = analizy_software_list(software_list, api_key)
    print("Анализ списка ПО окончен")
    
    head = ["ПО","Весрия", "Результат", "CVE", "Info"]
    
    final = []
    
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile, delimiter=';',
                                quotechar='|', quoting=csv.QUOTE_MINIMAL)
        writer.writerow(head)
        for r in result:
            writer.writerow([
                r['software'], 
                r['version'], 
                '+' if len(r['cve_info']) > 0 else '-',
                ', '.join(r['cve_info'][0]['cve']) if len(r['cve_info']) > 0 else '-',
                r['cve_info'][0]['link'] if len(r['cve_info']) > 0 else '-'
                ])
            for cve in r['cve_info'][1:]:
                writer.writerow(['','', '', ', '.join(cve['cve']), cve['link']])
    print("Результат сохранен в " + output_file)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--software-file", dest="file", help="Путь к списку программ для анализа.",type=str)
    parser.add_argument("-o", "--output-file", dest="output_file", help="Путь к файлу результату. По умолчанию result.csv",type=str, default='output.csv')
    parser.add_argument("-k", "--api-key", dest="api_key", help="API ключ для запросов к Valnurs. Можно также передать через переменную VT_API_KEY",type=str)

    args = parser.parse_args()
    main(args)
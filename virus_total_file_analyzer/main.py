from tabulate import tabulate
import requests as re
import time
import argparse
import os

FILE_UPLOAD_API = "https://www.virustotal.com/api/v3/files"
ANALYSES_RESULT_API = "https://www.virustotal.com/api/v3/analyses/{id}"
BEHAVIOUR_API = "https://www.virustotal.com/api/v3/files/{id}/behaviours"

def upload_file(path: str, api_key: str) -> str:
    headers = {"x-apikey" : api_key}
    with open(path, "rb") as file:
        files = {"file": (path, file)}
        response = re.post(FILE_UPLOAD_API, headers=headers, files=files)
    if response.status_code != 200:
        print(f"Virus total вернул код {response.status_code}")
        print(response.json())
        exit(1)

    result = response.json()
    return result['data']['id']

def get_analyse_result(id: str, api_key: str, waiting_sec: int) -> dict:
    headers = {"x-apikey" : api_key}
    
    for i in range(waiting_sec):
        response = re.get(ANALYSES_RESULT_API.format(id = id), headers=headers)
        if response.status_code != 200:
            print(f"Virus total вернул код {response.status_code}")
            print(response.json())
            exit(1)
            
        result = response.json()
        status = result['data']['attributes']['status']
        if status == 'queued':
            if i != 0 and i % 10 == 0:
                print(f"Ожидание окончания анализа файла. Осталось {waiting_sec - i} из {waiting_sec} секунд отведенный для ожидания")
            time.sleep(1)
        elif status == 'completed':
            return result
        else:
            print(f"Virus total вернул статус {status}")
            print(response.json())
            exit(1)
    
    print("Файл не был проанализирован за установленное время.")
    exit(1)
    
        
def get_behaviour_info(sha256: str, api_key: str) -> dict:
    headers = {"x-apikey" : api_key}
    response = re.get(BEHAVIOUR_API.format(id = sha256), headers=headers)
    
    if response.status_code != 200:
        print(f"Virus total вернул код {response.status_code}")
        print(response.json())
        exit(1)
        
    result = response.json()
    behaviour = result['data']
    
    behaviour_info = {}
    behaviour_info['description'] = []
    behaviour_info['ips'] = []
    behaviour_info['domains'] = []
    
    
    for b in behaviour:
        attr = b['attributes']
        if attr.get('mitre_attack_techniques'):
            mitres = attr['mitre_attack_techniques']
            for m in mitres:
                behaviour_info['description'].append(m['signature_description'])
        if attr.get('signature_matches'):
            mitres = attr['signature_matches']
            for m in mitres:
                behaviour_info['description'].append(m['description'])
        if attr.get('dns_lookups'):
            dns = attr['dns_lookups']
            for m in dns:
                if m.get('hostname'):
                    behaviour_info['domains'].append(m['hostname'])
                if m.get('resolved_ips'):
                    behaviour_info['ips'] += m['resolved_ips']
    
    return behaviour_info

def print_table(data: dict) -> None:
    head = ["Анализатор","Найдена уязвимость", "Результат", "Категория", "Версия анализатора"]
    
    results = data['data']['attributes']['results']
    detected_list = []
    undetected_list = []

    for k, v in results.items():
        if v['result'] != None: 
            detected_list.append([k, '+', v['result'], v['category'], v['engine_version'] ])
        else: 
            undetected_list.append([k, '-', '-', v['category'], v['engine_version']])
    
    result_final = detected_list + undetected_list
    
    print(tabulate(result_final, headers=head, tablefmt="grid"))
    
def print_results(file: str, data: dict, behaviour: dict):
    if len(behaviour['description']) != 0:
        print("\nПоведение файла:")
        for b in set(behaviour['description']):
            print('* ' + b)
    if len(behaviour['domains']) != 0:
        print("\nФайл пытается установить соединение с доменными именами:")
        for h in behaviour['domains']:
            print('* ' + h)
    if len(behaviour['ips']) != 0:
        print("\nФайл пытается установить соединение с ip:")
        for i in behaviour['ips']:
            print('* ' + str(i))
    print("\nСводка по обнаруженным уязвимостям:")
    print_table(data)
    
def main(args: any) -> None:
    api_key = args.api_key
    timeout = args.timeout
    file = args.file
    
    if api_key == None:
        api_key = os.getenv("VT_API_KEY")
        
    if timeout <= 0:
        print("Время ожидания результатов анализа файла не может быть меньше либо равно 0")
        exit(1)
    if api_key == '':
        print("Api-key не может быть пустым. Используйте флаг -k или переменную VT_API_KEY")
        exit(1)
    
    print("Анализируемый файл: " + file)
    
    id = upload_file(file, api_key)
    
    print("Данные отправлены на анализ. Id: " + id)
    analyse_data = get_analyse_result(id, api_key, timeout)
    print("Данные проанализированы.")
    
    file_sha256 = analyse_data['meta']['file_info']['sha256']
    behaviour = get_behaviour_info(file_sha256, api_key)
    print_results(file, analyse_data, behaviour)
    
    
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", dest="file", help="Путь к анализируемому файлу.",type=str)
    parser.add_argument("-k", "--api-key", dest="api_key", help="API ключ для запросов к Virus total. Можно также передать через переменную VT_API_KEY",type=str)
    parser.add_argument("-t", "--waiting-time", dest="timeout", help="Время ожидания результатов анализа файла (пока он в очереди) в секундах. По умолчанию 60 секунд",type=int, default=60)

    args = parser.parse_args()
    main(args)
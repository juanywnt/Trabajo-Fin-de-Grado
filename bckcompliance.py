import datetime
import boto3
import boto3.session
import subprocess
import json
import re
import remediation as rm

s3 = boto3.client('s3')
def list_s3_buckets():
    # Call S3 to list buckets
    response = s3.list_buckets()
    # Get the list of buckets from the response
    buckets = [bucket['Name'] for bucket in response['Buckets']]
    return buckets

def list_s3_objects(bucket):
    response=s3.list_objects_v2(Bucket=bucket)
    return response['Contents']


def list_s3_object_versions(bucket):
    #exception handling if object versions do not exist
    try:
        result = s3.list_object_versions(Bucket=bucket)
    except:
        result = "No Versions"
    return result
def get_object_lock(bucket, object):
    #exception handling if object lock does not exist
    try:
        result = s3.get_object_lock_configuration(Bucket=bucket, Key=object)
    except:
        result = "No Object Lock"
    return result
def get_public_access(bucket):
    #exception handling if public access block does not exist
    try:
        result = s3.get_public_access_block(Bucket=bucket)
    except Exception:
        result = "No Public Access Block"
    return result

def get_bucket_logging(bucket):
    #exception handling if bucket logging does not exist
    try:
        result = s3.get_bucket_logging(Bucket=bucket)
        logging = result['LoggingEnabled']
    except Exception:
        logging = "No Logging"
    return logging

def get_bucket_encryption(bucket):
    #exception handling if bucket encryption does not exist
    try:
        result = s3.get_bucket_encryption(Bucket=bucket)
    except:
        result = "No Encryption"
    return result

def get_object_acl(bucket, object):
    #exception handling if object acl does not exist
    try:
        result = s3.get_bucket_acl(Bucket=bucket, Key=object)
        acl = result['Owner']['Grants']
    except:
        acl = "No ACL"
    return acl
def get_bucket_acl(bucket):
    #exception handling if bucket acl does not exist
    try:
        result = s3.get_bucket_acl(Bucket=bucket)
        acl = result['Owner']['Grants']
    except:
        acl = "No ACL"
    return acl

def get_object_encryption(bucket, object):
    #exception handling if object encryption does not exist
    try:
        
        result = s3.get_object(Bucket=bucket, Key=object)
        #new dictionary to store encryption information
        encryption = {}
        try:
           encryption['ServerSideEncryption'] = result['ServerSideEncryption']
        except KeyError:
            pass
        try:
            encryption['BucketKeyEnabled'] = result['BucketKeyEnabled']
        except KeyError:
            pass
        try:
            encryption['SSEKMSKeyId'] = result['SSEKMSKeyId']
        except KeyError:
            pass
        try:
            encryption['x-amz-server-side-encryption'] = result['ResponseMetadata']['HTTPHeaders']['x-amz-server-side-encryption']
        except KeyError:
            pass
        try:
            encryption['x-amz-server-side-encryption-aws-kms-key-id'] = result['ResponseMetadata']['HTTPHeaders']['x-amz-server-side-encryption-aws-kms-key-id']
        except KeyError:
            pass
        try:
            encryption['x-amz-server-side-encryption-bucket-key-enabled'] = result['ResponseMetadata']['HTTPHeaders']['x-amz-server-side-encryption-bucket-key-enabled']
        except KeyError:
            pass

        
        return encryption
    except:
        result = "No Object Encryption"
    return result

def get_bucket_policy(bucket):
    #exception handling if bucket policy does not exist
    try:
        response = s3.get_bucket_policy(Bucket=bucket)
        policy = response['Policy']
    except:
        policy = "No policy"    
    return policy
def get_bucket_location(Bucket):
    
    result = s3.get_bucket_location(Bucket=Bucket)['LocationConstraint']
    if result is None:
        result = boto3.session.Session().region_name       
    return result
def run_pandoc(input_file, output_file):
    command = [
        'pandoc',
        input_file,
        '-o',
        output_file,
        '--pdf-engine=pdflatex',  # Specifies to use pdflatex for PDF generation
        '--from=markdown+raw_tex'
        #,  # Allows raw LaTeX inside Markdown
        #'--template=template.latex'  # Use the custom LaTeX template
    ]
    subprocess.run(command, check=True)
def json_unwrapper(obj, file):
    policy_json = json.loads(obj)
    for key, value in policy_json.items():
        try:
            sub_json=json.loads(json.dumps(value, indent=4))
            for key, value in sub_json.items():
                file.write(f"| |{key}: {json.dumps(value)} |\n")
        except:
            file.write(f"| |{key}: {value} |\n")           
        
    file.write(f"| | }} |\n")
# Función para detectar información sensible
def search_sensitive_data(content):
    sensitive_patterns = [
        re.compile(r'\b\d{16}\b'),   #números de tarjeta de crédito
        re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),  #números de seguridad social
        re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'), #direcciones IP
        re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}') #direcciones de correo electrónico
    ]
    for pattern in sensitive_patterns:
        if pattern.search(content):
            return True
    return False

# Función para leer y analizar archivos
def read_and_analyze_file(bucket_name, file_key):
    obj = s3.get_object(Bucket=bucket_name, Key=file_key)
    content = obj['Body'].read().decode('utf-8')
    return search_sensitive_data(content)
import json




def discovery_report():
    #list all s3 buckets and objects
    buckets = list_s3_buckets() 
    s3findingsjson= open("s3findings.json", "w")
    with open("findings.md", "w") as f:
        today = datetime.datetime.now().strftime("%B %d, %Y")
        f.write("\\begin{titlepage}\n")
        f.write("\\begin{center}\n")
        f.write("\\Huge\\textbf{AWS S3 Buckets State Report}\\\\[10mm]\n")
        f.write("\\vspace{1.5cm}\n")
        f.write("\\Large{Report generated on " + today + "}\\\\[10mm]\n")
        f.write("\\vspace{1.5cm}\n")
        f.write("\\begin{minipage}{0.9\\textwidth}\n")
        f.write("\\normalsize\n")
        f.write("This document provides a detailed state report of AWS S3 Buckets including properties, configurations, and object details. Each section below details the properties and settings of an individual bucket.\n")
        f.write("\\end{minipage}\n")
        f.write("\\vfill\n")
        f.write("Trabajo Fin de Grado ETSIINF\n")
        f.write("\\end{center}\n")
        f.write("\\end{titlepage}\n")
        f.write("\\newpage\n")
        s3findingsjson.write("{\n")
        s3findingsjson.write("  \"buckets\": {\n")
        flag=0
        for bucket in buckets:
            if flag==1:
                s3findingsjson.write("    },\n")
            flag=1       
            f.write(f"## Bucket{bucket}\n")
            s3findingsjson.write(f"    \"{bucket}\": {{\n")
            f.write("| Bucket Properties | Value |\n")
            f.write("| --- | --- |\n")
            f.write(f"| Bucket ARN | arn:aws:s3:::{bucket} |\n")
            f.write(f"| Bucket Location | {get_bucket_location(Bucket=bucket)} |\n")
            
            ##????
            policy = get_bucket_policy(bucket)
            if policy != "No policy":
                f.write(f"| Bucket Policy | {{ |\n")
                json_unwrapper(policy, f)
            else:
                f.write("| Bucket Policy | No Policy |\n")
            acl = get_bucket_acl(bucket)
            if acl != "No ACL":
                f.write(f"| Bucket ACL | {{ |\n")
                json_unwrapper(policy, f)
                s3findingsjson.write(f"      \"ACL\": \"1\",\n")
            else:
                f.write(f"| Bucket ACL | No ACL |\n")
                s3findingsjson.write(f"      \"ACL\": \"0\",\n")
            f.write(f"| Bucket Logging | {get_bucket_logging(bucket)} |\n")
            f.write("\\newpage\n")
            f.write("### Public Access Configuration:\n") 
            
            public_access_block_configuration = get_public_access(bucket)['PublicAccessBlockConfiguration']
            f.write("| Configuration | Value |\n")
            f.write("| --- | --- |\n")
            s3findingsjson.write(f"      \"pubacc_config\": {{\n")
            flag2=0
            for key, value in public_access_block_configuration.items():
                if flag2==1:
                    s3findingsjson.write("        ,\n")
                flag2=1
                f.write(f"| {key} | {value} |\n")
                s3findingsjson.write(f"        \"{key}\": \"{value}\"")
            s3findingsjson.write("      },\n")
            f.write("### Bucket Encryption:\n")
            f.write("| Configuration | Value |\n")
            f.write("| --- | --- |\n")
            #error handling if bucket encryption does not exist
            try:
                server_side_encryption_configuration = get_bucket_encryption(bucket)['ServerSideEncryptionConfiguration']
                for key, value in server_side_encryption_configuration.items():
                    f.write(f"| {key} | {value} |\n")
                    s3findingsjson.write(f"      \"encryption\": \"{value}\",\n")

            except:
                f.write("| No Encryption | |\n")
                s3findingsjson.write(f"      \"encryption\": \"0\",\n")
            f.write("### Objects:\n")
            try:
                objects = list_s3_objects(bucket)
                f.write("| Object | ACL | Lock | Sensitive Data\n")
                f.write("| --- | ---|----|----|\n")
                s3findingsjson.write(f"    \"objects\": {{\n")
                
                flag2=0
                objencryption={}
                for obj in objects:
                    if flag2==1:
                        s3findingsjson.write("      },\n")
                    flag2=1
                    s3findingsjson.write(f"      \"{obj['Key']}\": {{\n")
                    repres = obj['Key']
                    encrlimpio = (get_object_encryption(bucket, repres))
                    acllimpio= get_object_acl(bucket, repres)
                    locklimpio= get_object_lock(bucket, repres)
                    
                    s3findingsjson.write(f"        \"acl\": \"{acllimpio}\",\n")
                    s3findingsjson.write(f"        \"object_lock\": \"{locklimpio}\",\n")     
                    s3findingsjson.write(f"        \"encryption\": \"{encrlimpio}\",\n")
                    if repres.lower().endswith(('.txt', '.csv')):
                        analysis = read_and_analyze_file(bucket, repres)
                        s3findingsjson.write(f"        \"sensitive_data\": \"{analysis}\"\n")
                        f.write(f"| {repres} | {acllimpio} | {locklimpio} | {analysis} \n")
                        if analysis:
                            try:
                                rm.process_file(bucket, repres)
                            except:
                                print("Error processing file")
                    else: 
                        s3findingsjson.write("        \"sensitive_data\": \"0\"\n")
                        analysis = "Not Checked"
                        f.write(f"| {repres} | {acllimpio} | {locklimpio} | {analysis} \n")
                    objencryption[repres]=encrlimpio 
                f.write("### Object Encryption:\n")
                f.write("|Object | Encryption|\n")
                f.write("| --- | ---|\n")
                for key, value in objencryption.items():
                    f.write(f"| {key} | {value} |\n")
            except:
                f.write("#### No Objects\n")
            s3findingsjson.write("      }\n")
            s3findingsjson.write("      }\n")
    s3findingsjson.write("    }\n")
    s3findingsjson.write("  }\n")
    s3findingsjson.write("}\n")
    s3findingsjson.close()
    run_pandoc('findings.md', 'findings.pdf')


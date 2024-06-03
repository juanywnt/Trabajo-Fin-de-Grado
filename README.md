# Trabajo-Fin-de-Grado
##Para ejecutar la herramienta:

1. Es necesario tener instalado y corriendo Docker en tu máquina, además, es necesario tener unas credenciales con permiso de acceso por CLI, otorgadas por un administrador de la cuenta de AWS, estas
además deberán tener permisos de lectura y escritura sobre S3 y sus objetos.

2. ejecutar en una terminal dentro de la carpeta de la herramienta >
	docker build -t imgtfg .  
Para crear la imagen de Docker que se va a utilizar, con nombre imgtfg en este caso

3. ejecutar >
	docker run -it --name tfg imgtfg 
Para crear un contenedor de nombre tfg utilizando la imagen previamente creada

Esto, por la opción -it, conectará la entrada y salida estándar del contenedor al terminal, de esta manera se nos abrirá la línea de comandos de la herramienta
en la que ahora mismo solo se encuentra el comando comm, por únicamente tener una funcionalidad

4. ejecutar >
	comm
Esto comenzará la ejecución de la herramienta sobre los buckets y objetos de s3

5. Para obtener los resultados es necesario acceder al volumen de almacenamiento del contenedor, en la carpeta \app se encuentran todos los archivos que genera la herramienta
aes_key.bin -binario con la clave de cifrado
findings.md -archivo de soporte que utiliza la herramienta para generar el pdf
findings.pdf -pdf de reporte del estado de s3
s3findings.json -resultado de análisis de la herramienta en formato json para facilitar tareas futuras

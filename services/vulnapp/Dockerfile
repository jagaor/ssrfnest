# Dockerfile para la VulnApp de SSRFNest
# Aplicación Flask deliberadamente vulnerable a SSRF con endpoint /fetch?url=
# Base ligera de Python 3.11
FROM python:3.11-slim

# Evita prompts interactivos durante la instalación de paquetes
ENV DEBIAN_FRONTEND=noninteractive

# Directorio de trabajo dentro del contenedor
WORKDIR /app

# Copia el fichero de dependencias desde la raíz del proyecto
COPY requirements.txt /app/requirements.txt

# Instala dependencias sin cachear para reducir tamaño de imagen
RUN pip install --no-cache-dir -r /app/requirements.txt

# Copia el código de la aplicación vulnerable
COPY services/vulnapp/app.py /app/app.py

# Puerto en el que escucha Flask
EXPOSE 5000

# Arranca la aplicación vulnerable
CMD ["python", "app.py"]

import os

def list_directory_contents():
    """
    Lista todos los archivos y carpetas en el directorio actual.
    """
    try:
        # Obtener la lista de archivos y directorios en la ruta actual
        contents = os.listdir('.')
        
        # Separar los directorios de los archivos para una mejor visualización
        directories = [item for item in contents if os.path.isdir(item)]
        files = [item for item in contents if os.path.isfile(item)]
        
        print("Contenido del directorio actual:")
        print("-------------------------------")
        
        print("\nDirectorios:")
        if directories:
            for d in directories:
                print(f"  - {d}/")
        else:
            print("  (No se encontraron directorios)")
            
        print("\nArchivos:")
        if files:
            for f in files:
                print(f"  - {f}")
        else:
            print("  (No se encontraron archivos)")

    except Exception as e:
        print(f"Ocurrió un error al intentar listar el directorio: {e}")

if __name__ == "__main__":
    list_directory_contents()

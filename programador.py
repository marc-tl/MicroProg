import tkinter as tk


class ProgrammingMode(tk.Text):
    def __init__(self, master, toggle_mode_callback, *args, **kwargs):
        super().__init__(master, *args, **kwargs)
        self.toggle_button = None
        self.scrollbar = None
        self.data_field = None
        self.address_field = None
        self.master = master
        self.toggle_mode_callback = toggle_mode_callback
        self.setup_ui()  # Inicialització de la interfície d'usuari

    """--------------------------------------
    Nom: setup_ui
    Funció: Configura la interfície d'usuari del mode Programming.
    Paràmetres: Cap
    Return: Cap
    --------------------------------------"""

    def setup_ui(self):
        self.master.grid_columnconfigure(1, weight=1)  # Configura la graella
        self.master.grid_rowconfigure(0, weight=1)

        # Inicialització del camp d'adreces com un widget de text desactivat
        self.address_field = tk.Text(self.master, width=4, height=40, state='disabled', padx=10)
        self.address_field.grid(row=1, column=0, sticky='ns')

        # Etiqueta per al text en blau fosc en el camp d'adreces
        self.address_field.tag_configure("blau", foreground="#0F0CFF")  # Blau fosc

        # Inicialització del camp de dades com un widget BlocCaret (classe anterior)
        self.data_field = tk.Text(self.master, width=23, height=40, wrap='none', padx=10)
        self.data_field.grid(row=1, column=1, sticky='nsew')

        # Configura la barra de desplaçament
        self.scrollbar = tk.Scrollbar(self.master, command=self.on_scroll)
        self.scrollbar.grid(row=1, column=2, sticky='ns')

        # Configura el vincle de la barra de desplaçament amb els camps d'adreces i de dades
        self.data_field.config(yscrollcommand=self.scrollbar.set)
        self.address_field.config(yscrollcommand=self.scrollbar.set)

        # Omple els camps amb les dades inicials
        self.omple_dades()

        # Enllaça els esdeveniments de la roda del ratolí per al desplaçament
        self.data_field.bind("<MouseWheel>", self.scroll)
        self.address_field.bind("<MouseWheel>", self.scroll)

        # Pel canvi de mode
        self.toggle_button = tk.Button(self.master, text="Learning Mode", command=self.toggle_mode_callback)
        self.toggle_button.grid(row=0, column=0, columnspan=3, sticky="ew", padx=10, pady=5)

        # Inhabilita el botó del mig del ratolí, que podria provocar que les adreces i el contingut no concordessin
        self.data_field.bind("<Button-2>", lambda e: "break")
        self.data_field.bind("<B2-Motion>", lambda e: "break")
        self.address_field.bind("<Button-2>", lambda e: "break")
        self.address_field.bind("<B2-Motion>", lambda e: "break")

        # Crides per a quan es prem una tecla, el botó esquerre del ratolí, i el botó de la roda del ratolí
        self.data_field.bind("<Key>", self.tecla_premuda)
        self.data_field.bind("<Button-1>", self.click)
        self.data_field.bind("<Button-2>", lambda e: "break")
        self.data_field.bind("<B2-Motion>", lambda e: "break")

        # Eliminació del cursor per defecte (línia vertical) configurant el temps d'intermitència a 0
        self.data_field.configure(insertontime=0)

        # Esdeveniments per les tecles de fletxa, per moure el cursor
        self.data_field.bind("<Left>", self.mou_cursor_esquerra)
        self.data_field.bind("<Right>", self.mou_cursor_dreta)
        self.data_field.bind("<Up>", self.mou_cursor_amunt)
        self.data_field.bind("<Down>", self.mou_cursor_avall)

        self.intermitencia_cursor()

    """--------------------------------------
    Nom: load_hex_data
    Funció: Carrega les dades hexadecimal al camp de dades.
    Paràmetres: hex_data (llista) - Les dades hexadecimal a carregar.
    Return: Cap
    --------------------------------------"""

    def load_hex_data(self, hex_data):
        self.data_field.delete('1.0', tk.END)
        bytes_per_linia = 8
        total_linies = (0x7FF8 // 8) + 1

        formatted_data = []
        for line_index in range(total_linies):
            line_start = line_index * bytes_per_linia
            line_end = line_start + bytes_per_linia
            line_data = hex_data[line_start:line_end] if line_start < len(hex_data) else []
            if len(line_data) < bytes_per_linia:
                line_data += ['00'] * (bytes_per_linia - len(line_data))
            formatted_data.append(' '.join(line_data))

        self.data_field.insert('1.0', '\n'.join(formatted_data))

    """--------------------------------------
    Nom: scroll
    Funció: Gestiona l'esdeveniment de la roda del ratolí per al desplaçament.
    Paràmetres: event - L'esdeveniment de desplaçament.
    Return: Cap
    --------------------------------------"""

    def scroll(self, event):
        delta = event.delta if event.delta else event.deltaY

        # Desplaça els camps d'adreces i de dades
        if delta > 0:
            self.address_field.yview_scroll(-1, "units")
            self.data_field.yview_scroll(-1, "units")
        else:
            self.address_field.yview_scroll(1, "units")
            self.data_field.yview_scroll(1, "units")
        return "break"  # Evita el processament per defecte de la roda del ratolí

    """--------------------------------------
    Nom: alineacio
    Funció: Alinea les adreces i el contingut del camp de dades.
    Paràmetres: event - L'esdeveniment de desplaçament.
    Return: Cap
    --------------------------------------"""

    def alineacio(self, event):
        view = self.data_field.yview()
        self.address_field.yview_moveto(view[0])

    """--------------------------------------
    Nom: omple_dades
    Funció: Omple els camps d'adreces i de dades amb les dades inicials.
    Paràmetres: Cap
    Return: Cap
    --------------------------------------"""

    def omple_dades(self):
        for addr in range(0, 0x7FF8 + 1, 8):  # Incrementa de 8 en 8, aturant-se a 0x7FF8
            address = f"{addr:04X}"  # Formata l'adreça com hexadecimal de 4 caràcters
            data_line = ' '.join(['00'] * 8)  # 8 parells de bytes per línia

            # Per l'última fila no afegir \n
            if addr != 0x7FF8:
                address += '\n'
                data_line += '\n'

            self.address_field.config(state='normal')
            self.address_field.insert('end', address, "blau")  # Aplica l'etiqueta "blau"
            self.address_field.config(state='disabled')

            self.data_field.insert('end', data_line)

        self.posar_cursor_inici()  # Estableix el cursor al primer caràcter després d'omplir

    """--------------------------------------
    Nom: on_scroll
    Funció: Sincronitza el desplaçament de la barra entre els camps d'adreces i de dades.
    Paràmetres: *args - Arguments del desplaçament.
    Return: Cap
    --------------------------------------"""

    def on_scroll(self, *args):
        self.address_field.yview(*args)
        self.data_field.yview(*args)

    """--------------------------------------
    Nom: mou_cursor_esquerra
    Funció: Mou el cursor cap a l'esquerra.
    Paràmetres: event - L'esdeveniment de tecla premuda.
    Return: Cap
    --------------------------------------"""

    def mou_cursor_esquerra(self, event):
        self.reset_intermitencia()  # Reinici de la intermitència per mostrar el cursor (comoditat visual)

        # Obtenció de la posició actual del cursor
        cursor_pos = self.data_field.index(tk.INSERT)
        line, col = map(int, cursor_pos.split('.'))

        if col > 0:
            # Comprovació per si la posició actual és l'inici d'un parell de bytes o un espai
            if col % 3 == 0:
                new_col = col - 2  # Desplaçament al final del parell de bytes anterior
            else:
                new_col = col - 1  # Desplaçament una posició a l'esquerra

            self.data_field.mark_set(tk.INSERT, f"{line}.{new_col}")

        else:
            if line > 1:
                # Mou el cursor al final de la línia anterior (just abans del salt de línia)
                self.data_field.mark_set(tk.INSERT, f"{line - 1}.end")
                # Ajustem per no acabar just després d'un '\n' que podria haver al final de la línia
                self.data_field.mark_set(tk.INSERT, f"{tk.INSERT} - 1c")
                self.data_field.see(tk.INSERT)  # Assegura que el cursor és visible després de moure'l

        return "break"  # Afegir el break anul·la el comportament per defecte de les fletxes

    """--------------------------------------
    Nom: mou_cursor_dreta
    Funció: Mou el cursor cap a la dreta.
    Paràmetres: event - L'esdeveniment de tecla premuda.
    Return: Cap
    --------------------------------------"""

    def mou_cursor_dreta(self, event):
        self.reset_intermitencia()  # Reinici de la intermitència per mostrar el cursor (comoditat visual)

        # Obtenció de la posició actual del cursor
        cursor_pos = self.data_field.index(tk.INSERT)
        line, col = map(int, cursor_pos.split('.'))
        line_end_col = len(self.data_field.get(f"{line}.0", f"{line}.end"))

        if col < line_end_col - 1:
            # Comprovació per si la posició actual és al final d'un parell de bytes
            if col % 3 == 1:
                new_col = col + 2  # Salt de l'espai cap al següent parell de bytes
            else:
                new_col = col + 1  # Desplaçament una posició a la dreta

            self.data_field.mark_set(tk.INSERT, f"{line}.{new_col}")

        else:
            # Si el cursor ja és al final de la línia, mou el cursor a la línia següent
            total_lines = int(self.data_field.index("end-1c").split('.')[0])
            if line < total_lines:
                # Mou el cursor al principi de la següent línia
                self.data_field.mark_set(tk.INSERT, f"{line + 1}.0")
                self.data_field.see(tk.INSERT)  # Assegura que el cursor és visible després de moure'l

        return "break"  # Afegir el break anul·la el comportament per defecte de les fletxes

    """--------------------------------------
    Nom: mou_cursor_amunt
    Funció: Mou el cursor cap amunt.
    Paràmetres: event - L'esdeveniment de tecla premuda.
    Return: Cap
    --------------------------------------"""

    def mou_cursor_amunt(self, event):
        self.reset_intermitencia()  # Reinici de la intermitència per mostrar el cursor (comoditat visual)
        cursor_pos = self.data_field.index(tk.INSERT)
        line, col = map(int, cursor_pos.split('.'))

        # Comprovar si el cursor ja està a la primera línia
        if line > 1:
            self.data_field.tag_remove("block_caret", "1.0", "end")
            self.data_field.mark_set(tk.INSERT, f"{line - 1}.{col}")
            self.insert_block_caret()

        self.alineacio(event)
        return "break"

    """--------------------------------------
    Nom: mou_cursor_avall
    Funció: Mou el cursor cap avall.
    Paràmetres: event - L'esdeveniment de tecla premuda.
    Return: Cap
    --------------------------------------"""

    def mou_cursor_avall(self, event):
        self.reset_intermitencia()  # Reinici de la intermitència per mostrar el cursor (comoditat visual)
        cursor_pos = self.data_field.index(tk.INSERT)
        line, col = map(int, cursor_pos.split('.'))
        total_lines = int(self.data_field.index("end-1c").split('.')[0])

        # Comprovar si el cursor ja està a l'última línia
        if line < total_lines - 1:
            self.data_field.tag_remove("block_caret", "1.0", "end")
            self.data_field.mark_set(tk.INSERT, f"{line + 1}.{col}")
            self.insert_block_caret()

        self.alineacio(event)
        return "break"

    """--------------------------------------
    Nom: posar_cursor_inici
    Funció: Posiciona el cursor a l'inici de tot.
    Paràmetres: Cap
    Return: Cap
    --------------------------------------"""

    def posar_cursor_inici(self):
        self.data_field.mark_set(tk.INSERT, "1.0")  # Posicionament del cursor a l'inici
        self.data_field.see(tk.INSERT)  # Cursor visible
        self.data_field.focus()  # Focus al camp de dades
        self.alineacio(self)

    """--------------------------------------
    Nom: intermitencia_cursor
    Funció: Gestiona la intermitència del cursor de bloc.
    Paràmetres: Cap
    Return: Cap
    --------------------------------------"""

    def intermitencia_cursor(self):
        if self.data_field.tag_ranges("block_caret"):
            self.data_field.tag_remove("block_caret", "1.0", "end")  # Amaga el cursor de bloc
        else:
            self.insert_block_caret()  # Mostra el cursor de bloc

        # Reinici del cicle d'intermitència
        self.intermitencia = self.data_field.after(500, self.intermitencia_cursor)

    """--------------------------------------
    Nom: actualitza_bloc_caret
    Funció: Actualitza el cursor de bloc a la posició actual del cursor.
    Paràmetres: Cap
    Return: Cap
    --------------------------------------"""

    def actualitza_bloc_caret(self):
        self.data_field.tag_remove("block_caret", "1.0", "end")  # Eliminació de l'etiqueta del cursor de bloc
        self.insert_block_caret()  # Inserció del cursor de bloc a la posició actual

    """--------------------------------------
    Nom: reset_intermitencia
    Funció: Reinicia la intermitència del cursor de bloc.
    Paràmetres: Cap
    Return: Cap
    --------------------------------------"""

    def reset_intermitencia(self):
        if hasattr(self, 'intermitencia'):
            self.data_field.after_cancel(self.intermitencia)  # Cancel·lació del cicle d'intermitència existent

        # Actualització del cursor de bloc per reflectir la posició actual del cursor
        self.data_field.after_idle(self.actualitza_bloc_caret)

        # Inici d'un nou cicle d'intermitència
        self.intermitencia = self.data_field.after(500, self.intermitencia_cursor)

    """--------------------------------------
    Nom: tecla_premuda
    Funció: Gestiona la pulsació de tecles.
    Paràmetres: event - L'esdeveniment de tecla premuda.
    Return: Cap
    --------------------------------------"""

    def tecla_premuda(self, event):
        self.alineacio(event)
        if not self.input_valid(event.char):
            return "break"  # Ignorar les entrades que no siguin caràcters hexadecimals vàlids

        cursor_pos = self.data_field.index(tk.INSERT)  # Posició actual del cursor
        line, col = map(int, cursor_pos.split('.'))

        # Obtenim el nombre total de columnes i línies
        total_lines = 4096  # (2^15 adreces/8)=4096
        total_cols = 23  # 8 bytes (16 columnes) + 7 separacions

        # Comprovem si el cursor està a l'última posició possible
        if line == total_lines and col == total_cols - 1:
            self.data_field.delete(cursor_pos)
            self.data_field.insert(cursor_pos, event.char.upper())  # Inserim el caràcter
            self.posar_cursor_inici()  # Tornem el cursor a l'inici després d'escriure
        else:
            if col % 3 == 0 or col % 3 == 1:  # El cursor es troba dins d'un parell de bytes
                # Sobreescriu el caràcter a la posició actual del cursor
                self.data_field.delete(cursor_pos)
                self.data_field.insert(cursor_pos, event.char.upper())

                # Si el cursor és a la primera posició d'un parell de bytes, es mou a la segona posició
                if col % 3 == 0:
                    next_pos = f"{line}.{col + 1}"
                else:
                    # Si està a la segona posició, es mou a la primera posició del següent parell de bytes
                    next_pos = f"{line}.{col + 2}"

                # Comprova si es troba al final de la línia, si és així es mou al començament de la següent línia.
                if col + 1 >= total_cols:
                    next_pos = f"{line + 1}.0"
                self.data_field.mark_set(tk.INSERT, next_pos)
            else:
                # El cursor no es troba dins d'un parell de bytes (en mig)
                new_pos = f"{line}.{col + 1}"
                self.data_field.mark_set(tk.INSERT, new_pos)

                # Inserció del caràcter a aquesta nova posició i desplaçament del cursor a la següent posició vàlida
                self.data_field.insert(tk.INSERT, event.char.upper())
                self.data_field.mark_set(tk.INSERT, f"{line}.{col + 2}")
                cursor_pos = self.data_field.index(tk.INSERT)
                self.data_field.delete(cursor_pos)

        # Reinici de la intermitència per mostrar el cursor després de moure's
        self.reset_intermitencia()
        return "break"

    """--------------------------------------
    Nom: click
    Funció: Esdeveniment per al clic del ratolí.
    Paràmetres: event - L'esdeveniment de clic del ratolí.
    Return: Cap
    --------------------------------------"""

    def click(self, event):
        self.reset_intermitencia()  # Reinici de la intermitència per mostrar el cursor

    """--------------------------------------
    Nom: input_valid
    Funció: Comprovació per si l'input és un caràcter hexadecimal vàlid.
    Paràmetres: char (str) - El caràcter a comprovar.
    Return: bool - True si el caràcter és vàlid, False en cas contrari.
    --------------------------------------"""

    def input_valid(self, char):
        return char.upper() in "0123456789ABCDEF" and len(char) == 1

    """--------------------------------------
    Nom: insert_block_caret
    Funció: Inserta el cursor de bloc a la posició actual.
    Paràmetres: Cap
    Return: Cap
    --------------------------------------"""

    def insert_block_caret(self):
        cursor_pos = self.data_field.index(tk.INSERT)
        self.data_field.tag_add("block_caret", cursor_pos, f"{cursor_pos}+1c")
        self.data_field.tag_configure("block_caret", background="black", foreground="white")


"""--------------------------------------
Nom: setup_programming_mode
Funció: Configura el mode Programming i carrega les dades hexadecimal.
Paràmetres: master (tk.Tk), toggle_mode_callback (funció), hex_data (llista) - La finestra principal, la funció de canvi de mode i les dades hexadecimal.
Return: ProgrammingMode - La instància del mode Programming configurada.
--------------------------------------"""


def setup_programming_mode(master, toggle_mode_callback, hex_data):
    app = ProgrammingMode(master, toggle_mode_callback)
    app.load_hex_data(hex_data)
    return app

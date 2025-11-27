from datetime import datetime

score_table = {
    "magic_number":10,
    "number_of_sections":0.5,
    "low_number_of_sections":10,
    "aslr":10,
    "e_lfanew":15,
    "flags":75,
    "pe_sign":10,
    "ratio":10,
    "sections_names":15,
    "aslr":15,
    "code_cave":15,
    "aep":25
}

def check_magic_number(pe):
    #mn = hex(pe.DOS_HEADER.e_magic)
    mn = pe.DOS_HEADER.e_magic
    if mn != 0x5a4d:
        count=score_table["magic_number"]
        return count,f"Le nombre magique est invalide (différent de MZ / 0x5a4d) : {mn}"
    return 0

# Le "e_lfanew" pointe vers la table PE
# Il doit être plus petit que la taille du fichier
def check_e_lfanew(summary):
    eln = summary["DOS_Header"]["e_lfanew"]
    file_size = summary["File"]["Size"]
    eln = int(eln,16) # converti en base 10
    if eln > file_size:
        count=score_table["e_lfanew"]
        return count,"L'entête e_lfanew est invalide (plus grand que la taille du fichier)."
    return 0

def check_flags(summary):
    sec = []
    for s in summary["Sections"]:
        if "WRITE" in s["Flags"] and "EXECUTE" in s["Flags"]: # /!\ SECTION WRITE + EXECUTE
            sec.append(s["Name"])
    if len(sec)!=0:
        count=score_table["flags"]
        alert_string = "Au moins une section est à la fois en écriture et en exécution.\nSection(s) concernée(s) : "
        for name in sec:
            alert_string+=name+"\n"
        print(alert_string)
        return count,alert_string
    return 0

def pe_sign(pe):
    eln = pe.NT_HEADERS.Signature
    #eln = hex(eln)
    if eln != 0x00004550:
        count=score_table["pe_sign"]
        return count,f"La signature PE est invalide : {eln}"
    print("C'est OK pour la signature")
    return 0

def ratio_virtual_raw_size(pe):
    jokers = [".data",".tls",".bss",".ndata"] # ces sections font exception
    sections = pe.sections
    lsec = []
    for s in sections:
        sname = s.Name.decode(errors="ignore").rstrip("\x00")
        if sname not in jokers:
            ratio = s.Misc_VirtualSize / s.SizeOfRawData
            #print("VSize :",s.Misc_VirtualSize,"\nRawSize :",s.SizeOfRawData,"\nRatio :",ratio)
            if (ratio<0.5) or (ratio>3):
                lsec.append(sname)
    if len(lsec)!=0:
        count=score_table["ratio"]
        alert_string = "Au moins une section a un ratio VirtualSize/RawSize atypique.\n"
        for name in lsec:
            alert_string+=name+"\n"
        print(alert_string)
        return count,alert_string
    return 0


def get_sections_number(summary):
    nb = len(summary["Sections"])
    diff = nb-10
    if diff > 0:
        count = score_table["number_of_sections"]
        count*=diff
        return count,f"Il y a {nb} sections au total, ce qui est élevé."
    if nb-5 < 0:
        count = score_table["low_number_of_sections"]
        return count,f"Il y a {nb} sections au total, ce qui est peu."
    return 0

def sections_names(pe):
    suspicious = ["UPX","themida","taggant","vmp","MPRESS"] # liste de noms de section suspects
    sections = pe.sections
    lsec = []
    for s in sections:
        sname = s.Name.decode(errors="ignore").rstrip("\x00")
        for ssp in suspicious:
            if (ssp in sname) or sname == ".":
                lsec.append(sname)
    if len(lsec)!=0:
        count=score_table["sections_names"]
        alert_string = "Au moins une section a un nom suspect.\n"
        for name in lsec:
            alert_string+=name+"\n"
        print(alert_string)
        return count,alert_string
    return 0


def aslr(pe):
    dll_char = pe.OPTIONAL_HEADER.DllCharacteristics
    has_aslr = bool(dll_char & 0x40)
    ts = pe.FILE_HEADER.TimeDateStamp
    dtc = datetime.fromtimestamp(ts)
    print("Date de compilation =",dtc)
    # Si pas d'ASLR
    if not has_aslr:
        if ts-1325376000 > 0:
            return score_table["aslr"], f"L'ASLR n'est pas activé sur un exécutable moderne (2012 et plus).\
            Date de compilation indiquée : {dtc}" # si compilé après 2012
        return score_table["aslr"], f"L'ASLR n'est pas activé. Date de compilation indiquée : {dtc}"
    return 0

def code_cave(pe):
    suspicious_sections = []
    min_cave_size = 512
    for s in pe.sections:
        flags = s.Characteristics
        if not (flags & 0x20000000): # regarder les sections exécutables
            continue
        data = s.get_data()
        if not data:
            continue
        max_run = 0
        current_run = 0
        empty_bytes = {0x00,0xFF,0x90} # bytes considérés comme étant vides
        
        for b in data:
            if b in empty_bytes:
                current_run+=1
                if current_run - max_run > 0:
                    max_run = current_run
                    # extraire la plus grande séquence vide de la section
            else:
                current_run=0
                # l'espace vide de la section est interrompu

        if max_run - min_cave_size >= 0:
            name = s.Name.decode(errors="ignore").rstrip("\x00")
            suspicious_sections.append((name,max_run))
            # tableau avec nom de la section + taille du code cave trouvé
    
    if len(suspicious_sections)!=0:
        count=score_table["code_cave"]
        alert_string = "Au moins une section possède un grand espace vide (potentiel code cave).\n"
        for name,size in suspicious_sections:
            alert_string+=f" - Section {name} : séquence vide maximale de {size} octets.\n"
        print(alert_string)
        return count,alert_string
    return 0

def aep_out_of_text(pe):
    aep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    # On cherche dans quelle section se trouve l'AEP
    aep_section_name = None

    for s in pe.sections:
        section_start = s.VirtualAddress
        section_end = section_start + s.Misc_VirtualSize

        # Est-ce que l'AEP tombe dans cette section ?
        if  section_start <= aep < section_end:
            aep_section_name = s.Name.decode(errors="ignore").rstrip("\x00")
            break

    # Sections légitimes
    valid_code_sections = {".text",".code","CODE","TEXT",".itext"}

    if aep_section_name is None: # /!\ trouvée dans aucune section
        count = score_table["aep"]
        return count,f"L'AddressOfEntryPoint (0x{aep:X}) ne se trouve dans aucune section connue."
    if aep_section_name not in valid_code_sections:
        count = score_table["aep"]
        return count,f"L'AddressOfEntryPoint (0x{aep:X}) se trouve dans la section '{aep_section_name}' au lieu de .text/.code."
    #print(aep_section_name)
    return 0


# ------------------------------------ LIST OF ALL FUNCTIONS / TOUTES LES FONCTIONS --------

check_list = [
    check_magic_number,
    pe_sign,
    ratio_virtual_raw_size,
    sections_names,
    aslr,
    code_cave,
    aep_out_of_text
    ]
check_w_sum = [
    check_e_lfanew,
    check_flags,
    get_sections_number
    ]

def main(sum):
    check_magic_number(sum)

if __name__ == "__main__":
    main()


#!/usr/bin/env python3
"""Garante que os textos do pacote que vão para o config.xml sejam ASCII.

Por que isto existe
-------------------
O pfSense copia alguns campos dos XMLs do pacote para dentro do config.xml:
o <descr> do info.xml, e os blocos <menu>, <service> e <tabs> do XML da
interface. O escritor de XML do pfSense 2.7.x faz

    htmlentities($valor)

sem a flag ENT_XML1, o que transforma "usuário" em "usu&aacute;rio". E
&aacute; NÃO é uma entidade válida em XML: só &amp;, &lt;, &gt;, &quot;,
&apos; e as numéricas são. O resultado é um config.xml que o próprio pfSense
não consegue reler; ele então salva o arquivo como config.xml.bad e RESTAURA
UM BACKUP — ou seja, a instalação do pacote reverte a configuração do
firewall.

O pfSense 2.8 passou a usar htmlentities($valor, ENT_XML1) e não tem esse
problema, mas o pacote precisa funcionar nas duas versões.

Conclusão: nos campos que vão para o config.xml, só ASCII. Os rótulos e textos
de ajuda dos formulários não passam por aqui (o pfSense os lê do XML a cada
exibição), então esses podem ter acentos à vontade.

Uso: python3 build/check-config-ascii.py <arquivos .xml...>
"""
import sys
import xml.etree.ElementTree as ET

# Caminhos, dentro de cada XML, cujo texto o pfSense guarda no config.xml.
# Ver install_package_xml() em /etc/inc/pkg-utils.inc.
CONFIG_BOUND = [
    # info.xml
    "./package/name",
    "./package/internal_name",
    "./package/descr",
    "./package/website",
    "./package/version",
    "./package/configurationfile",
    # <packagegui> (guarita.xml, guaritagroups.xml)
    "./name",
    "./version",
    "./menu/name",
    "./menu/tooltiptext",
    "./menu/section",
    "./menu/url",
    "./service/name",
    "./service/rcfile",
    "./service/executable",
    "./service/description",
    "./tabs/tab/text",
    "./tabs/tab/url",
    "./include_file",
    "./filter_rules_needed",
]


def non_ascii(s):
    return [c for c in s if ord(c) > 127]


def check(path):
    problems = []
    try:
        tree = ET.parse(path)
    except ET.ParseError as e:
        return [f"{path}: XML malformado: {e}"]
    root = tree.getroot()

    for xp in CONFIG_BOUND:
        for el in root.findall(xp):
            if el.text is None:
                continue
            bad = non_ascii(el.text)
            if bad:
                chars = " ".join(sorted(set(bad)))
                preview = " ".join(el.text.split())[:70]
                problems.append(
                    f"{path}: <{el.tag}> em {xp} tem caractere nao-ASCII [{chars}]\n"
                    f"    texto: {preview}\n"
                    f"    este campo vai para o config.xml e corromperia o "
                    f"arquivo no pfSense 2.7.x"
                )
    return problems


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    all_problems = []
    for path in sys.argv[1:]:
        all_problems += check(path)

    if all_problems:
        print("FALHOU: texto nao-ASCII em campos que vao para o config.xml\n")
        for p in all_problems:
            print("  " + p)
        print("\nTroque os acentos por ASCII nesses campos. Os rotulos e textos")
        print("de ajuda dos formularios podem manter os acentos.")
        return 1

    print(f"ok: {len(sys.argv) - 1} arquivo(s) sem acentos nos campos do config.xml")
    return 0


if __name__ == "__main__":
    sys.exit(main())

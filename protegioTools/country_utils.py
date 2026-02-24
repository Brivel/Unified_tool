"""
Utilitaires pour identifier le pays à partir du domaine TLD
"""

# Dictionnaire complet des extensions de domaines et leurs pays/régions correspondants
TLD_TO_COUNTRY = {
    # Domaines génériques
    'com': 'États-Unis (Générique)',
    'org': 'International (Générique)',
    'net': 'International (Générique)',
    'edu': 'États-Unis (Éducation)',
    'gov': 'États-Unis (Gouvernement)',
    'mil': 'États-Unis (Militaire)',
    'int': 'International',
    
    # Europe
    'fr': 'France',
    'de': 'Allemagne',
    'uk': 'Royaume-Uni',
    'gb': 'Royaume-Uni',
    'es': 'Espagne',
    'it': 'Italie',
    'nl': 'Pays-Bas',
    'be': 'Belgique',
    'ch': 'Suisse',
    'at': 'Autriche',
    'se': 'Suède',
    'no': 'Norvège',
    'dk': 'Danemark',
    'fi': 'Finlande',
    'pl': 'Pologne',
    'cz': 'République Tchèque',
    'sk': 'Slovaquie',
    'hu': 'Hongrie',
    'ro': 'Roumanie',
    'bg': 'Bulgarie',
    'hr': 'Croatie',
    'si': 'Slovénie',
    'gr': 'Grèce',
    'pt': 'Portugal',
    'ie': 'Irlande',
    'lu': 'Luxembourg',
    'mt': 'Malte',
    'cy': 'Chypre',
    'rs': 'Serbie',
    'ua': 'Ukraine',
    'by': 'Biélorussie',
    'ru': 'Russie',
    
    # Amérique du Nord
    'ca': 'Canada',
    'mx': 'Mexique',
    'us': 'États-Unis',
    
    # Amérique du Sud
    'br': 'Brésil',
    'ar': 'Argentine',
    'cl': 'Chili',
    'co': 'Colombie',
    'pe': 'Pérou',
    've': 'Venezuela',
    'ec': 'Équateur',
    'uy': 'Uruguay',
    'py': 'Paraguay',
    'bo': 'Bolivie',
    
    # Asie
    'cn': 'Chine',
    'jp': 'Japon',
    'kr': 'Corée du Sud',
    'kp': 'Corée du Nord',
    'in': 'Inde',
    'pk': 'Pakistan',
    'bd': 'Bangladesh',
    'th': 'Thaïlande',
    'vn': 'Vietnam',
    'ph': 'Philippines',
    'id': 'Indonésie',
    'my': 'Malaisie',
    'sg': 'Singapour',
    'tw': 'Taïwan',
    'hk': 'Hong Kong',
    'mo': 'Macao',
    'th': 'Thaïlande',
    'la': 'Laos',
    'kh': 'Cambodge',
    'mm': 'Myanmar',
    'lk': 'Sri Lanka',
    'np': 'Népal',
    'bt': 'Bhoutan',
    'af': 'Afghanistan',
    'ir': 'Iran',
    'iq': 'Irak',
    'sa': 'Arabie Saoudite',
    'ae': 'Émirats Arabes Unis',
    'kw': 'Koweït',
    'qa': 'Qatar',
    'bh': 'Bahreïn',
    'om': 'Oman',
    'ye': 'Yémen',
    'jo': 'Jordanie',
    'lb': 'Liban',
    'sy': 'Syrie',
    'tr': 'Turquie',
    'il': 'Israël',
    'ps': 'Palestine',
    
    # Afrique
    'eg': 'Égypte',
    'za': 'Afrique du Sud',
    'gh': 'Ghana',
    'ng': 'Nigéria',
    'ke': 'Kenya',
    'tz': 'Tanzanie',
    'ug': 'Ouganda',
    'ma': 'Maroc',
    'tn': 'Tunisie',
    'dz': 'Algérie',
    'sd': 'Soudan',
    'et': 'Éthiopie',
    'cm': 'Cameroun',
    'ci': 'Côte d\'Ivoire',
    'sn': 'Sénégal',
    'bf': 'Burkina Faso',
    'ml': 'Mali',
    'ne': 'Niger',
    'gn': 'Guinée',
    'mg': 'Madagascar',
    'mu': 'Maurice',
    'sc': 'Seychelles',
    'bw': 'Botswana',
    'zm': 'Zambie',
    'zw': 'Zimbabwe',
    'mz': 'Mozambique',
    'ao': 'Angola',
    'na': 'Namibie',
    'ls': 'Lesotho',
    'sz': 'Eswatini',
    'rw': 'Rwanda',
    'bi': 'Burundi',
    'dj': 'Djibouti',
    'er': 'Érythrée',
    'so': 'Somalie',
    'ss': 'Soudan du Sud',
    
    # Océanie
    'au': 'Australie',
    'nz': 'Nouvelle-Zélande',
    'fj': 'Fidji',
    'pw': 'Palaos',
    'sb': 'Îles Salomon',
    'vu': 'Vanuatu',
    'ws': 'Samoa',
    'ki': 'Kiribati',
    'to': 'Tonga',
    'tv': 'Tuvalu',
    
    # Domaines spéciaux
    'eu': 'Union Européenne',
    'tel': 'Télécommunications',
    'xxx': 'Adulte',
    'app': 'Applications',
    'dev': 'Développement',
    'io': 'Territoire Britannique',
    'co': 'Colombie/Générique',
    'tv': 'Tuvalu/Vidéo',
    'ws': 'Samoa/Web',
    'cc': 'Îles Cocos',
    'info': 'Information',
    'biz': 'Business',
    'name': 'Noms',
}

def get_country_from_domain(domain):
    """
    Extrait le pays à partir de l'extension du domaine (TLD)
    
    Args:
        domain (str): Le nom de domaine (ex: "example.fr")
    
    Returns:
        str: Le pays correspondant au TLD, ou "Domaine générique" si non trouvé
    """
    if not domain:
        return "Inconnu"
    
    # Convertir en minuscules
    domain = domain.lower().strip()
    
    # Extraire l'extension (TLD)
    parts = domain.split('.')
    
    if len(parts) < 2:
        return "Invalide"
    
    # Récupérer le dernier segment (TLD principal)
    tld = parts[-1]
    
    # Si c'est un domaine multi-niveaux (exemple: .co.uk)
    if len(parts) >= 3:
        combined_tld = f"{parts[-2]}.{parts[-1]}"
        if combined_tld in ['co.uk', 'co.nz', 'co.za', 'co.ke', 'com.br', 'com.mx']:
            # Chercher le pays du TLD principal
            if parts[-1] in TLD_TO_COUNTRY:
                return TLD_TO_COUNTRY[parts[-1]]
    
    # Chercher dans le dictionnaire
    if tld in TLD_TO_COUNTRY:
        return TLD_TO_COUNTRY[tld]
    
    # Si non trouvé, retourner "Domaine générique" ou le TLD
    return f"TLD: {tld}"


def get_country_flag(country_name):
    """
    Retourne un emoji/symbole pour le pays
    
    Args:
        country_name (str): Le nom du pays
    
    Returns:
        str: Un symbole ou emoji représentant le pays
    """
    country_flags = {
        'France': '🇫🇷',
        'Allemagne': '🇩🇪',
        'Royaume-Uni': '🇬🇧',
        'Espagne': '🇪🇸',
        'Italie': '🇮🇹',
        'Pays-Bas': '🇳🇱',
        'Belgique': '🇧🇪',
        'Suisse': '🇨🇭',
        'Autriche': '🇦🇹',
        'Suède': '🇸🇪',
        'Norvège': '🇳🇴',
        'Danemark': '🇩🇰',
        'Finlande': '🇫🇮',
        'Pologne': '🇵🇱',
        'Canada': '🇨🇦',
        'États-Unis': '🇺🇸',
        'Mexique': '🇲🇽',
        'Brésil': '🇧🇷',
        'Chine': '🇨🇳',
        'Japon': '🇯🇵',
        'Corée du Sud': '🇰🇷',
        'Inde': '🇮🇳',
        'Australie': '🇦🇺',
        'Nouvelle-Zélande': '🇳🇿',
        'Égypte': '🇪🇬',
        'Afrique du Sud': '🇿🇦',
        'Union Européenne': '🇪🇺',
        'International (Générique)': '🌐',
        'États-Unis (Générique)': '🇺🇸',
    }
    
    for key in country_flags:
        if key.lower() in country_name.lower():
            return country_flags[key]
    
    return '🌍'

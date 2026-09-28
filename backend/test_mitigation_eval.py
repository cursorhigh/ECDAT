import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
django.setup()

from segments.ml.analysis.models import AnalysisRun
from segments.scraping.discovery.models import CryptoAsset
from segments.mitigation.mitigation_agent import MitigationAgent, rules
from segments.reporting.dashboard.views import _asset_risk, _priority_score, _pqc_replacement

run = AnalysisRun.objects.filter(pk=14).first()
cas = list(CryptoAsset.objects.filter(session_id=run.session_id).order_by('id'))

assets_data = []
for ca in cas:
    key, label, _ = _asset_risk(ca)
    score = _priority_score(ca, key)
    qv = ca.family in ('rsa', 'ecc', 'dsa', 'dh') or ca.algorithm.upper() in ('RSA', 'ECC', 'ECDSA', 'ECDH', 'ED25519', 'EDDSA', 'DSA', 'DH', 'X25519')
    
    algo_upper = (ca.algorithm or '').upper()
    if ca.family in ('rsa', 'ecc', 'dsa', 'dh') or any(k in algo_upper for k in ('RSA', 'ECC', 'ECDSA', 'ECDH', 'ED25519', 'DSA', 'DH', 'X25519')):
        cat = 'PUBLIC_KEY'
    elif ca.family in ('aes', 'des', '3des') or any(k in algo_upper for k in ('AES', 'DES', '3DES', 'BLOWFISH', 'RC4', 'CHACHA20')):
        cat = 'SYMMETRIC'
    elif ca.family in ('hash',) or any(k in algo_upper for k in ('SHA', 'MD5', 'HMAC')):
        cat = 'HASH'
    else:
        cat = 'UNKNOWN'
        
    is_weak = algo_upper in ('MD5', 'SHA-1', 'SHA1', 'DES', '3DES', 'RC4', 'RC2', 'BLOWFISH')
    
    if is_weak:
        prio = 'URGENT' if score >= 80 else 'HIGH'
        overall_risk = 'HIGH'
    elif qv:
        prio = 'HIGH'
        overall_risk = 'HIGH'
    else:
        prio = 'LOW' if score < 40 else 'MEDIUM'
        overall_risk = 'LOW' if key == 'pqc' else 'MEDIUM'
        
    role = ''
    if 'cert' in (ca.location or '').lower() or 'demo_rsa' in (ca.location or '').lower():
        role = 'certificate'
    elif algo_upper in ('ECDSA', 'ED25519'):
        role = 'digital_signature'
    elif algo_upper in ('ECDH', 'X25519', 'DH'):
        role = 'key_establishment'
    elif 'test_crypto_example' in (ca.location or '').lower():
        role = 'password_hashing'
        
    cbom = {
        'asset_id': ca.name,
        'name': ca.name,
        'algorithm': ca.algorithm,
        'family': ca.family,
        'location': {'file': ca.location or ca.source_path},
        'parameters': {'key_size': ca.key_size, 'curve': ca.curve},
        'crypto_role': role,
    }
    
    assets_data.append({
        'id': f'asset-{ca.pk}',
        'asset_id': ca.name,
        'algorithm': ca.algorithm,
        'family': ca.family,
        'algorithm_category': cat,
        'classical_security': 'WEAK' if is_weak else 'STANDARD',
        'overall_risk': overall_risk,
        'migration_priority': prio,
        'quantum_vulnerable': qv,
        'hndl_risk': 'HIGH' if 'cert' in (ca.location or '').lower() else '',
        'service': rules.service_for_location(ca.location or ca.source_path),
        'cbom_asset': cbom,
        'crypto_role': role,
    })

bundle = {
    'application': 'ECDAT Demo',
    'repository': {},
    'risk_context': {'network': {'publicly_accessible': False}},
    'assets': assets_data,
}

agent = MitigationAgent(use_llm=False)
doc = agent.generate(bundle)
summary = doc['summary']
print('Mitigation Document Summary:')
print('Assets count:', summary['assets'])
print('Wave 1:', summary['wave1'])
print('Wave 2:', summary['wave2'])
print('Wave 3:', summary['wave3'])
print('Wave total:', summary['wave1'] + summary['wave2'] + summary['wave3'])
print('Quantum vulnerable:', summary['quantum_vulnerable'])
print('Effort estimate quarters:', summary['effort_estimate_quarters'])

effort_range = rules.compute_effort_range(doc['rows'])
print('Effort range:', effort_range)

print('\nRows:')
for r in doc['rows']:
    print(f"Wave {r['migration_wave']} | Algo: {r['algorithm']} | Prio: {r['migration_priority']} | Replacement: {r['migration_impact']['replacement']} | Service: {r['service']}")

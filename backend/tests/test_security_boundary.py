"""Offline security tests: no provider credentials or heavyweight AI imports."""
import importlib.util
from pathlib import Path

import pytest
from flask import Flask, jsonify

spec = importlib.util.spec_from_file_location("security", Path(__file__).parents[1] / "app/security.py")
security = importlib.util.module_from_spec(spec)
spec.loader.exec_module(security)
PASSWORD = "test-only-password-not-for-deploy-123456"


@pytest.fixture
def client():
    app = Flask(__name__)
    app.config.update(EXPERIMENT_USERNAME="operator", EXPERIMENT_PASSWORD=PASSWORD)
    security.install_security(app)

    @app.route('/api/resource/<simulation_id>', methods=['GET', 'POST', 'DELETE'])
    def resource(simulation_id):
        return jsonify(success=True)

    @app.route('/api/failure')
    def failure():
        return jsonify(error="PROVIDER_SECRET", traceback="PRIVATE_PATH"), 500

    @app.route('/health')
    def health():
        return jsonify(status="ok")

    return app.test_client()


def test_fail_closed():
    with pytest.raises(RuntimeError):
        security.install_security(Flask(__name__))


def test_debug_rejected():
    app = Flask(__name__)
    app.config.update(EXPERIMENT_USERNAME="operator", EXPERIMENT_PASSWORD=PASSWORD, DEBUG=True)
    with pytest.raises(RuntimeError):
        security.install_security(app)


@pytest.mark.parametrize('method', ['get', 'post', 'delete', 'options'])
def test_unauthenticated_denied(client, method):
    assert getattr(client, method)('/api/resource/sim_123').status_code == 401


def test_wrong_password(client):
    assert client.get('/api/resource/sim_123', auth=('operator', 'wrong')).status_code == 401


def test_health(client):
    assert client.get('/health').status_code == 200


def test_authorized(client):
    response = client.get('/api/resource/sim_123', auth=('operator', PASSWORD))
    assert response.status_code == 200
    assert 'Access-Control-Allow-Origin' not in response.headers
    assert response.headers['Cache-Control'] == 'no-store'


def test_mutation_csrf(client):
    assert client.post('/api/resource/sim_123', auth=('operator', PASSWORD)).status_code == 403
    assert client.post('/api/resource/sim_123', auth=('operator', PASSWORD), headers={'X-MiroFish-Request': '1'}).status_code == 200


def test_cross_site(client):
    assert client.get('/api/resource/sim_123', auth=('operator', PASSWORD), headers={'Sec-Fetch-Site': 'cross-site'}).status_code == 403


@pytest.mark.parametrize('payload', [
    {'simulation_id': '../secret'}, {'project_id': '/tmp'},
    {'report_id': '..\\secret'}, {'platform': '../../private'},
    {'simulation_id': None}, {'platform': []},
    {'interviews': [{'platform': '../reddit'}]},
])
def test_body_traversal(client, payload):
    assert client.post('/api/resource/sim_123', auth=('operator', PASSWORD), headers={'X-MiroFish-Request': '1'}, json=payload).status_code == 400


@pytest.mark.parametrize('suffix', ['..?platform=reddit', 'sim_123?platform=..%2Fsecret', 'sim_123?platform=reddit&platform=..%2Fsecret'])
def test_url_traversal(client, suffix):
    assert client.get('/api/resource/' + suffix, auth=('operator', PASSWORD)).status_code == 400


def test_form_traversal(client):
    assert client.post('/api/resource/sim_123', auth=('operator', PASSWORD), headers={'X-MiroFish-Request': '1'}, data={'project_id': '../secret'}).status_code == 400


def test_errors_redacted(client):
    response = client.get('/api/failure', auth=('operator', PASSWORD))
    assert response.status_code == 500
    assert response.json == {'success': False, 'error': 'Internal server error'}

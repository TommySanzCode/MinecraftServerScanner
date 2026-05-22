from minecraft_server_scanner.mcscans import DEFAULT_PAGE_SIZE, McScansClient, dataset_target_files, server_from_record
from minecraft_server_scanner.models import McScansDataset, McScansDatasetFile


def test_server_from_record_maps_mcscans_shape_to_local_result():
    server = server_from_record(
        {
            "hostname": "170.205.25.236",
            "port": 25565,
            "motd": "Hello",
            "motd_normalized": "Hello",
            "software": "Paper",
            "version": "1.21.7",
            "favicon": {"hash": "abc"},
            "ping": {"protocol": 772, "latency": 12.5},
            "playerStats": {"onlinePlayers": 3, "maxPlayers": 100},
            "geolocation": {"country": "US", "org": "Example Host"},
            "tags": ["historical"],
            "timestamp": "2026-05-19T16:34:51Z",
        },
        "java",
    )
    result = server.to_server_result()

    assert server.address == "170.205.25.236:25565"
    assert result.edition == "java"
    assert result.protocol == 772
    assert result.players_online == 3
    assert result.favicon_present is True
    assert "software=Paper" in result.notes


def test_dataset_target_files_filters_zmap_csv_files():
    datasets = [
        McScansDataset(
            dataset_id="scan-1",
            files=[
                McScansDatasetFile(dataset_id="scan-1", name="Java_results.json"),
                McScansDatasetFile(dataset_id="scan-1", name="Java_zmap.csv"),
                McScansDatasetFile(dataset_id="scan-1", name="Bedrock_zmap.csv.gz"),
            ],
        )
    ]

    files = dataset_target_files(datasets)

    assert [file.name for file in files] == ["Java_zmap.csv", "Bedrock_zmap.csv.gz"]
    assert files[0].download_url == "https://data.mcscans.fi/scan-1/Java_zmap.csv"


def test_client_search_tracks_page_metadata_without_network():
    class FakeClient(McScansClient):
        def _get_json(self, url):
            assert "page=3" in url
            return {
                "totalServers": 45,
                "servers": [
                    {
                        "hostname": "203.0.113.1",
                        "port": 25565,
                        "playerStats": {"onlinePlayers": 0, "maxPlayers": 20},
                        "ping": {"protocol": 769, "latency": 0},
                    }
                ],
            }

    result = FakeClient().search_servers(page=3)

    assert result.page == 3
    assert result.page_size == DEFAULT_PAGE_SIZE
    assert result.total_servers == 45
    assert result.servers[0].address == "203.0.113.1:25565"

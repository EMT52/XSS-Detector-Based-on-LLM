# Source Code of XSSKy

This document will introduce the setup and usage of XSSKy.

## Setup

### Step 1: Setting the Environment 

**1) Install the Dependencies**

```shell
pip3 install -r requirements.txt
```

**2) Install Neo4j**
Download and install Neo4j (available at https://neo4j.com/download/).

### Step2: Preparing Neo4j databases

**1) Construct Neo4j Databases**

To support the analysis of XSSKy, you need to construct the Code Property Graphs for the target applications. Then import them into Neo4j. You can follow the instructions at `https://https://github.com/ticktac-project/tchecker` to build the CPGs.

After constructing Neo4j databases, move them to `PUT_extractor/databases/`:

```shell
mv /path/to/neo4j PUT_extractor/databases/
```

**2) Configure Neo4j connectors**

Next, you should edit the configuration files of Neo4j and XSSKy to ensure that XSSKy can properly connect to the databases.

For Neo4j, you can edit its configuration file (usually in `/path/to/neo4j/conf/neo4j.conf`). Please pay attention to these statements:

```
dbms.connector.http.listen_address=:PORT_A
dbms.connector.bolt.listen_address=:PORT_B
```

For XSSKy, you can edit the `PUT_extractor/config/neo4j.json` file to set up its connections to Neo4j. The content looks like the following:

```json
{
  // ...
  "database-name": {
    "NEO4J_HOST": "localhost",
    "NEO4J_PORT": PORT_A,
    "NEO4J_USERNAME": "neo4j",
    "NEO4J_PASSWORD": "neo4j",
    "NEO4J_DATABASE": "neo4j",
    "NEO4J_PROTOCOL": "http"
  }
  //...
}
```

> Note that the listening ports of the Neo4j (e.g., PORT_A and PORT_B) should not be occupied and should be kept consistent with the XSSKy configuration.

### Step3: Install the instrumented PHP

We provide the instrumented version of PHP in this repository. Follow the commands to install it in your system environment:

```shell
tar -xzvf php-instr.tar.gz
cd php-instr
./configure --prefix=/usr/local/php-instr --with-apxs2=/usr/bin/apxs
make -j$(nproc)
sudo make install
sudo ln -s /usr/local/php-instr/lib/apache2/modules/libphp.so /usr/lib/apache2/modules/
sudo systemctl restart apache2
```

This instrumented version of PHP will report the characters blocked by sanitizers, which works as a feedback mechanism for our PUT fuzzer.


## Usage

XSSKy consists of two parts: PUT extraction and PUT fuzzing. This section will guide you to utilize each of them.

### Step1: Potential paths collection

XSSky works on the static reports produced by TChecker. Refer to `https://github.com/ticktac-project/tchecker` and place the reported path (in the form of a series of node ids) in `PUT_extractor/storage/taint_flows/[target].json`.

### Step2: PUT extraction

You can extract PUTs from the target application with the following commands:

```shell
cd PUT_extractor
python PUT_extractor.py --target=WordPress
```

The extracted PUTs are under `PUT_extractor/storage/PUT/target/[path_id]`. Then you need to move the extracted PUTs into the web server directory (e.g. `/var/www/html`). The following command is for reference:

```shell
mv PUT_extractor/storage/PUT/WordPress/1038817 /var/www/html/WordPress/
```

### Step3: PUT fuzzing

Once the PUTs are placed under the web directory, run the following command to test the PUTs:

```shell
cd PUT_fuzzer
python PUT_fuzzer.py
```

The results will be output to `PUT_fuzzer/output/results.json`. This file contains
only the current run. Before replacement, the previous file is archived under
`PUT_fuzzer/output/history/`; results and durations are not merged across runs.
Saving uses an atomic replacement so an interrupted write does not truncate the
previous results.

Use `--output output/php-app.json` to choose a separate output file for a project
or concurrent run. Concurrent processes should use different output paths.

Each PUT starts with `note`, followed by `payload` for confirmed findings, then
`test_count` for the combined stage count. Findings use `Vulnerability found by
standard test` or `Vulnerability found by LLM`. Other results use `No vulnerability
found` or `Testing incomplete`.

`standard_result` records the standard-stage count and any error. `LLM_result`
records the provider, generated and tested payload counts, and any LLM error.
Errors are recorded in their respective stages. The legacy `safe_files` group
includes both negative and incomplete tests. Timeouts, context parsing failures,
and stages with no tested payloads produce `Testing incomplete` when no finding
is confirmed.

Every unconfirmed LLM result includes `failed_response` with the full original
API response body, including responses that generated payloads without a finding.
When no response was received, this field is `null` and `error` records the
request failure. Errors retain the exception type and message, including JSON
parsing failures and empty model content. Historical reports whose response was
never recorded also use `null`; their original response cannot be reconstructed.

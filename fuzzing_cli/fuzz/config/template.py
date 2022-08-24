from jinja2 import Environment

CONFIG_TEMPLATE = """analyze:
  # We need to know where the dependencies live
  # remappings:
    #   - "@openzeppelin=./node_modules/@openzeppelin"
    #   - "@ozUpgradesV3=OpenZeppelin/openzeppelin-contracts-upgradeable@3.3.0"
  {% if remappings %}remappings: {% for rm in remappings %}
    - "{{ rm }}"{% endfor %}{% endif %}

  # Sometimes you want to enforce a specific solidity version
  # solc-version: "0.6.12"
  {% if solc_version %}solc-version: "{{ solc_version }}"{% endif %}
  {% if scribble_path %}scribble-path: {{ scribble_path }}{% endif %}
  {% if no_assert %}no-assert: {{ no_assert }}{% endif %}

fuzz:
  ide: {{ ide }}

  quick_check: {{ quick_check }}

  # Tell the CLI where to find the compiled contracts and compilation artifacts
  build_directory: {{ build_directory }}

  # Tell the CLI where to find the contracts source
  sources_directory: {{ sources_directory }}

  # The following address is going to be the main target for the fuzzing campaign
  # deployed_contract_address: "0x48b8050b4174f7871ce53AaF76BEAcA765037BFf"

  # This parameter tells the fuzzer to also fuzz these contracts
  # additional_contracts_addresses:
  #   - "0x0eb775F99A28cb591Fa449ca74eF8E7cEd3A609a"
  #   - "0x21C62e9c9Fcb6622602eBae83b41abb6b28d7256"

  # Number of CPU cores to run fuzzing
  number_of_cores: {{ number_of_cores }}

  # When the campaign is created it'll get a name <prefix>_<random_characters>
  campaign_name_prefix: {{ campaign_name_prefix }}

  # Set a default project to which your campaigns will be attached to
  # project: "my project name"

  # Set the API key, which can be obtained from the Diligence Fuzzing Dashboard
  # key: "bHd3...ddsds"

  # Point to your ganache node which holds the seed 🌱
  rpc_url: {{ rpc_url }}

  # This is the contract that the campaign will show coverage for, map issues to, etc.
  # It's a list of all the relevant contracts (don't worry about dependencies, we'll get those automatically 🙌){% if targets %}
  targets:{% for target in targets %}
    - "{{ target }}"{% endfor %}
{% else %}
  # targets:
    # entire directory with contracts
    # - "contracts/Proxy"
    # individual files
    # - "contracts/Token.sol"
{% endif %}
"""

env = Environment()
template = env.from_string(CONFIG_TEMPLATE)


def generate_yaml(context) -> str:
    return template.render(context)

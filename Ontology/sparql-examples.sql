PREFIX main: <http://www.semanticweb.org/rycht/ontologies/cyber_security_ontology#>
prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#>
prefix owl: <http://www.w3.org/2002/07/owl#>

SELECT ?cve ?title ?oval ?ovalTitle
WHERE {
  ?cve a <https://cve.mitre.org/about/terminology.html#CVE>.
  ?cve main:hasTitle ?title.
  ?oval a <https://oval.mitre.org/language/version5.11/OVAL>.
  ?oval main:hasCVE ?cve.
  ?oval main:hasTitle ?ovalTitle
}
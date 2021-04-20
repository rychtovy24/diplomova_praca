PREFIX main: <http://www.semanticweb.org/rycht/ontologies/cyber_security_ontology#>
PREFIX platform: <http://www.semanticweb.org/rycht/ontologies/cyber_security_ontology/platform#>
PREFIX cve: <https://cve.mitre.org/about/terminology.html#>
PREFIX oval:<https://oval.mitre.org/language/version5.11/OVAL>

SELECT ?cve ?title
WHERE {
  ?cve a cve:CVE.
  ?cve main:hasTitle ?title.
  ?oval a oval:.
  ?oval main:hasCVE ?cve.
  ?oval main:affectedPlatform platform:Microsoft_Windows_8
}

PREFIX main: <http://www.semanticweb.org/rycht/ontologies/cyber_security_ontology#>
PREFIX product: <http://www.semanticweb.org/rycht/ontologies/cyber_security_ontology/product#>
PREFIX cve: <https://cve.mitre.org/about/terminology.html#>
PREFIX oval:<https://oval.mitre.org/language/version5.11/OVAL>

SELECT ?cve ?title
WHERE {
  ?cve a cve:CVE.
  ?cve main:hasTitle ?title.
  ?oval a oval:.
  ?oval main:hasCVE ?cve.
  ?oval main:affectedProduct product:GitHub_Enterprise
}


PREFIX main: <http://www.semanticweb.org/rycht/ontologies/cyber_security_ontology#>
PREFIX cve: <https://cve.mitre.org/about/terminology.html#>
PREFIX oval:<https://oval.mitre.org/language/version5.11/OVAL>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

SELECT ?oval ?title ?family ?familyName ?platform ?platformName
WHERE {
  ?oval a oval:.
  ?oval main:hasTitle ?title.
  ?oval main:affectedFamily ?family.
  ?family rdfs:label ?familyName.
  ?oval main:affectedPlatform ?platform.
  ?platform rdfs:label ?platformName.
  NOT EXISTS {
    ?oval main:affectedProduct ?product.
  }
}


PREFIX main: <http://www.semanticweb.org/rycht/ontologies/cyber_security_ontology#>
PREFIX platform: <http://www.semanticweb.org/rycht/ontologies/cyber_security_ontology/platform#>
PREFIX cve: <https://cve.mitre.org/about/terminology.html#>
PREFIX oval:<https://oval.mitre.org/language/version5.11/OVAL>

SELECT ?cve ?title (COUNT(?oval) as ?count)
WHERE {
  ?cve a cve:CVE.
  ?cve main:hasTitle ?title.
  ?oval a oval:.
  ?oval main:hasCVE ?cve.
} 
GROUP BY ?cve ?title
ORDER BY DESC(?count)


PREFIX main: <http://www.semanticweb.org/rycht/ontologies/cyber_security_ontology#>
PREFIX platform: <http://www.semanticweb.org/rycht/ontologies/cyber_security_ontology/platform#>
PREFIX cve: <https://cve.mitre.org/about/terminology.html#>
PREFIX oval:<https://oval.mitre.org/language/version5.11/OVAL>

SELECT ?cve ?title ?product ?family1 ?family2
WHERE {
  ?cve a cve:CVE.
  ?cve main:hasTitle ?title.
  ?oval1 a oval:.
  ?oval1 main:hasCVE ?cve.
  ?oval1 main:affectedProduct ?product.
  ?oval1 main:affectedFamily ?family1.
  ?oval2 a oval:.
  ?oval2 main:hasCVE ?cve.
  ?oval2 main:affectedProduct ?product.
  ?oval2 main:affectedFamily ?family2.
  FILTER (?family1 != ?family2).
} 
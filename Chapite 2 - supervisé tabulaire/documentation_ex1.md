# Documentation - Détection de maliciel

## Objectif

Le notebook `ex1 - détection maliciel.ipynb` entraîne un modèle de machine learning supervisé pour classer des fichiers en deux catégories :

- `Benign` : fichier légitime ;
- `Malware` : fichier malveillant.

Le modèle apprend à partir du fichier `data/dataset_malware.csv`.

## Fonctionnement général

Le notebook suit les étapes suivantes :

1. Charger les bibliothèques et le jeu de données.
2. Explorer les données.
3. Préparer les colonnes utilisées par le modèle.
4. Séparer les données en entraînement et en test.
5. Entraîner un classifieur.
6. Prédire la classe des données de test.
7. Évaluer les résultats.

## 1. Chargement des données

```python
import pandas as pd

data = pd.read_csv('data/dataset_malware.csv')
```

`pandas` permet de lire le fichier CSV et de le manipuler sous la forme d'un tableau appelé `DataFrame`.

## 2. Exploration des données

Le notebook vérifie :

- la taille du jeu de données avec `data.shape` ;
- les premières lignes avec `data.head()` ;
- les noms des colonnes avec `data.columns` ;
- les valeurs manquantes avec `data.isna().sum()` ;
- les classes possibles de la cible `Malware` ;
- la répartition entre fichiers bénins et malveillants.

Cette étape sert à comprendre les données avant de lancer l'apprentissage et à repérer d'éventuels problèmes, comme des valeurs manquantes ou des colonnes non numériques.

## 3. Préparation des données

La colonne `Name` est supprimée : elle identifie le fichier, mais ne doit pas servir de caractéristique d'apprentissage.

```python
data.drop(['Name'], axis=1, inplace=True)
```

La colonne `Malware` est la variable cible. Elle est séparée des autres colonnes :

```python
features = data.drop(['Malware'], axis=1)
labels = data['Malware']
```

- `features` contient les informations utilisées pour faire la prédiction ;
- `labels` contient la réponse attendue (`Benign` ou `Malware`).

Les données sont ensuite divisées en deux parties :

```python
train_features, test_features, train_labels, test_labels = train_test_split(
    features, labels, test_size=0.2
)
```

80 % des données servent à entraîner le modèle et 20 % servent à vérifier ses performances sur des exemples qu'il n'a pas vus.

## 4. Entraînement du modèle

Le notebook importe actuellement `LogisticRegression` :

```python
from sklearn.linear_model import LogisticRegression
```

La régression logistique produit une prédiction de classe à partir des caractéristiques du fichier.

### Attention à la version actuelle du notebook

Le texte de conclusion parle d'un KNN avec `K=5`, mais la cellule active mélange les deux modèles :

```python
classifier = LogisticRegression(n_neighbors=5)
```

`n_neighbors` est un paramètre de `KNeighborsClassifier`, pas de `LogisticRegression`.

Pour utiliser une régression logistique :

```python
classifier = LogisticRegression(max_iter=1000)
```

Pour utiliser le KNN décrit dans la conclusion :

```python
from sklearn.neighbors import KNeighborsClassifier

classifier = KNeighborsClassifier(n_neighbors=5)
```

Dans les deux cas, l'apprentissage est réalisé avec :

```python
classifier.fit(train_features, train_labels)
```

## 5. Prédictions

Une fois le modèle entraîné, il prédit les classes des données de test :

```python
predicted_labels = classifier.predict(test_features)
```

Chaque ligne est classée comme `Benign` ou `Malware`.

## 6. Évaluation

### Accuracy

L'accuracy représente la proportion de prédictions correctes :

```python
accuracy = accuracy_score(test_labels, predicted_labels)
```

Par exemple, une accuracy de 0,96 signifie que 96 % des exemples de test ont été correctement classés. Cette mesure doit toutefois être interprétée avec la répartition des classes, surtout si les catégories sont déséquilibrées.

### Matrice de confusion

La matrice de confusion compare les classes réelles et les classes prédites :

```python
cm = confusion_matrix(test_labels, predicted_labels)
```

Elle permet de distinguer :

- les fichiers bénins correctement reconnus ;
- les malwares correctement détectés ;
- les faux positifs : fichiers bénins classés comme malwares ;
- les faux négatifs : malwares classés comme bénins.

En cybersécurité, les faux négatifs sont particulièrement importants, car ils correspondent à des malwares non détectés.

## Exécution

Depuis VS Code :

1. Ouvrir `ex1 - détection maliciel.ipynb`.
2. Sélectionner un environnement Python contenant `pandas`, `scikit-learn`, `seaborn` et `matplotlib`.
3. Exécuter les cellules dans l'ordre.
4. Vérifier l'accuracy et la matrice de confusion.

Le chemin du CSV est relatif au dossier du notebook :

```text
data/dataset_malware.csv
```

Il faut donc conserver cette organisation des fichiers.

## Limites

Les résultats peuvent changer d'une exécution à l'autre, car la séparation entraînement/test n'utilise pas de `random_state`. Pour obtenir une séparation reproductible, on peut écrire :

```python
train_features, test_features, train_labels, test_labels = train_test_split(
    features,
    labels,
    test_size=0.2,
    random_state=42,
    stratify=labels
)
```

Une bonne accuracy seule ne suffit pas à juger un détecteur de malware : il est également utile d'examiner le rappel de la classe `Malware`, les faux négatifs et éventuellement la précision, le rappel et le score F1.

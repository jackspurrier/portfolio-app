FROM python:3.6
COPY . /portfolio-app/PortfolioApp_Updated
WORKDIR /portfolio-app/PortfolioApp_Updated
RUN pip install -r requirements.txt
EXPOSE 8880
ENTRYPOINT ["python"]
CMD ["app.py"]

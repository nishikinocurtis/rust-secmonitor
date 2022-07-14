use bollard::Docker;
use bollard::errors::Error;
use bollard::container::{CreateContainerOptions, Config, StartContainerOptions, TopOptions};
use bollard::models::ContainerTopResponse;

pub(crate) async fn create_and_run_container(
    image_name: &str,
) -> Result<ContainerTopResponse, Error> {
    let mut container_name: String = "secmonitor-".to_owned();
    container_name.push_str(image_name);

    let docker = Docker::connect_with_local_defaults()?;

    docker.ping().await?;

    println!("Docker client initialized");

    let options = Some(CreateContainerOptions{
        name: container_name.to_string(),
    });
    let config = Config {
        image: Some(image_name.to_string()),
        ..Default::default()
    };

    docker.create_container(options, config).await?;

    println!("Container created");

    docker.start_container(
        container_name.as_str(),
        None::<StartContainerOptions<String>>).await?;

    let process_info = docker.top_processes(
        container_name.as_str(),
        None::<TopOptions<String>>).await?;

    Ok(process_info)
}

pub(crate) fn stop_container(name: &str) -> Result<(), Error> {

    Ok(())
}